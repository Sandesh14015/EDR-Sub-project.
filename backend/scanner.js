import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import si from 'systeminformation';
import { saveEvents } from './database.js';
import { correlate } from './detection.js';

const suspiciousPorts = { 4444: 'Metasploit / Reverse Shell Default Port', 1337: 'Common Backdoor Port', 5555: 'Android ADB / Trojan Port', 6667: 'IRC / Botnet C2 Communication', 8888: 'Alternative HTTP / Common C2 Staging Port', 31337: 'Back Orifice / Trojan Port', 23: 'Insecure Telnet Protocol', 1080: 'SOCKS Proxy' };
const suspiciousProcesses = { 'cmd.exe': 'Windows Command Prompt making outbound network connection', 'powershell.exe': 'PowerShell making direct external network connection', 'pwsh.exe': 'PowerShell Core making direct external network connection', 'certutil.exe': 'CertUtil network activity', 'rundll32.exe': 'RunDLL32 network activity', 'wscript.exe': 'Windows Script Host network activity', 'cscript.exe': 'Console Script Host network activity', 'mshta.exe': 'Microsoft HTML Application Host network activity', 'regsvr32.exe': 'Regsvr32 network activity' };
const id = prefix => `${prefix}-${randomUUID().slice(0, 8).toUpperCase()}`;
export function isExternalIp(ip) {
  if (!isIP(ip)) return false;
  if (isIP(ip) === 6) return !/^(::1$|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return !(a === 10 || a === 127 || a === 0 || a === 192 && b === 168 || a === 172 && b >= 16 && b <= 31 || a === 169 && b === 254);
}
export async function systemConnections(limit = 50) {
  const [raw, processes] = await Promise.all([si.networkConnections(), si.processes()]);
  const names = new Map(processes.list.map(item => [item.pid, item.name]));
  return raw.filter(conn => conn.peerAddress && !['*', '0.0.0.0', '::'].includes(conn.peerAddress) && Number(conn.peerPort) > 0).slice(0, limit).map(conn => ({
    local_ip: conn.localAddress || '*', local_port: Number(conn.localPort) || 0,
    remote_ip: conn.peerAddress, remote_port: Number(conn.peerPort) || 0,
    status: conn.state || 'UNKNOWN', pid: Number(conn.pid) || null,
    process_name: conn.process || names.get(Number(conn.pid)) || (conn.pid ? `PID-${conn.pid}` : 'Unknown'),
    protocol: conn.protocol || 'TCP'
  }));
}

class Scanner {
  constructor() { this.timer = null; this.scanned = 0; this.alerts = 0; this.startedAt = null; this.seen = new Set(); this.busy = false; }
  status() { return { is_scanning: Boolean(this.timer), scanned_connections: this.scanned, alerts_generated: this.alerts, started_at: this.startedAt }; }
  start() {
    if (this.timer) return;
    this.startedAt = new Date().toISOString();
    this.timer = setInterval(() => this.scanOnce().then(events => { if (events.length) correlate(); }).catch(error => console.error('Scan cycle failed:', error)), 3000);
    this.timer.unref();
  }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }
  async scanOnce() {
    if (this.busy) return [];
    this.busy = true;
    try {
      const connections = await systemConnections(10000);
      const now = new Date().toISOString(), events = [], portsByIp = new Map();
      for (const conn of connections) {
        this.scanned++;
        const { local_ip, local_port, remote_ip, remote_port, status, pid, process_name } = conn;
        const protocol = String(conn.protocol).toUpperCase();
        if (!portsByIp.has(remote_ip)) portsByIp.set(remote_ip, new Set());
        portsByIp.get(remote_ip).add(remote_port);
        const telemetry = {
          event_id: id('SYS'), timestamp: now, source: 'zeek', domain: 'Network', event_type: 'conn',
          src_ip: local_ip, src_port: local_port, dst_ip: remote_ip, dst_port: remote_port, protocol,
          severity: status === 'SYN_SENT' && isExternalIp(remote_ip) ? 3 : 1,
          signature: status === 'SYN_SENT' && isExternalIp(remote_ip) ? `Unacknowledged SYN probe by ${process_name} -> ${remote_ip}:${remote_port}` : `Connection [${status}] by ${process_name} -> ${remote_ip}:${remote_port}`,
          flow_id: `PID_${pid || 0}_${local_port}`, sensor_id: 'host-agent-live', raw_event: { process_name, pid, status }
        };
        events.push(telemetry);
        const processRule = suspiciousProcesses[process_name.toLowerCase()];
        for (const [key, severity, signature, rule] of [
          [`process_${process_name}_${remote_ip}_${remote_port}`, 9, processRule ? `INTRUSION ALERT: ${processRule} -> ${remote_ip}:${remote_port}` : null, 'SUSPICIOUS_OUTBOUND_PROCESS'],
          [`port_${remote_ip}_${remote_port}`, 8, suspiciousPorts[remote_port] ? `HIGH-RISK PORT DETECTED: Port ${remote_port} (${suspiciousPorts[remote_port]}) contacted by ${process_name}` : null, 'SUSPICIOUS_PORT_ALERT']
        ]) if (signature && isExternalIp(remote_ip) && !this.seen.has(key)) {
          this.seen.add(key); this.alerts++;
          events.push({ event_id: id('IDS'), timestamp: now, source: 'suricata', domain: 'Network', event_type: 'alert', src_ip: local_ip, src_port: local_port, dst_ip: remote_ip, dst_port: remote_port, protocol, severity, signature, flow_id: `PID_${pid || 0}`, sensor_id: 'host-ids-live', raw_event: { rule, process_name, pid, destination: `${remote_ip}:${remote_port}` } });
        }
      }
      for (const [ip, ports] of portsByIp) if (ports.size >= 6 && isExternalIp(ip) && !this.seen.has(`scan_${ip}`)) {
        this.seen.add(`scan_${ip}`); this.alerts++;
        events.push({ event_id: id('IDS'), timestamp: now, source: 'suricata', domain: 'Network', event_type: 'alert', src_ip: '127.0.0.1', dst_ip: ip, protocol: 'TCP', severity: 7, signature: `POTENTIAL PORT SCAN: ${ports.size} different destination ports contacted on ${ip}`, sensor_id: 'host-ids-live', raw_event: { rule: 'PORT_SCAN_DETECTED', ports_contacted: [...ports], target_ip: ip } });
      }
      if (events.length) saveEvents(events);
      return events;
    } finally { this.busy = false; }
  }
}
export const scanner = new Scanner();
