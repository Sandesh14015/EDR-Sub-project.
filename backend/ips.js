import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';

const runFile = promisify(execFile);
const blocked = new Map();
const invalid = new Set(['127.0.0.1', '::1', '0.0.0.0']);
const windows = process.platform === 'win32';
const ruleName = ip => `WayTrace_BLOCK_${ip.replaceAll(':', '_')}`;
async function command(file, args) {
  try { const { stdout, stderr } = await runFile(file, args, { windowsHide: true, timeout: 10000 }); return { ok: true, output: (stdout || stderr).trim() }; }
  catch (error) { return { ok: false, output: (error.stderr || error.message || '').trim() }; }
}
export async function blockIp(ip, reason = 'WayTrace Active Response Containment') {
  if (!isIP(ip) || invalid.has(ip)) return { success: false, message: 'Cannot block loopback or invalid address.' };
  const name = ruleName(ip);
  const inbound = windows ? await command('netsh', ['advfirewall', 'firewall', 'add', 'rule', `name=${name}_IN`, 'dir=in', 'action=block', `remoteip=${ip}`]) : await command('iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
  if (!inbound.ok) return { success: false, ip, message: `Failed to block ${ip}: ${inbound.output}`, details: inbound.output };
  const outbound = windows ? await command('netsh', ['advfirewall', 'firewall', 'add', 'rule', `name=${name}_OUT`, 'dir=out', 'action=block', `remoteip=${ip}`]) : await command('iptables', ['-A', 'OUTPUT', '-d', ip, '-j', 'DROP']);
  if (!outbound.ok) {
    if (windows) await command('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${name}_IN`]);
    else await command('iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
    return { success: false, ip, message: `Failed to block ${ip}: ${outbound.output}`, details: outbound.output };
  }
  const blocked_at = new Date().toISOString();
  blocked.set(ip, { ip, blocked_at, reason, rule_name: name });
  return { success: true, ip, message: `IP ${ip} has been blocked at the host firewall.`, details: outbound.output, blocked_at };
}
export async function unblockIp(ip) {
  if (!isIP(ip) || invalid.has(ip)) return { success: false, message: 'Invalid address.' };
  const name = ruleName(ip);
  const inbound = windows ? await command('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${name}_IN`]) : await command('iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
  const outbound = windows ? await command('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${name}_OUT`]) : await command('iptables', ['-D', 'OUTPUT', '-d', ip, '-j', 'DROP']);
  if (inbound.ok && outbound.ok) blocked.delete(ip);
  return { success: inbound.ok && outbound.ok, message: inbound.ok && outbound.ok ? `IP ${ip} unblocked.` : `Failed to unblock ${ip}: ${inbound.output || outbound.output}` };
}
export async function terminateProcess(pid, processName) {
  if (!Number.isSafeInteger(pid) || pid <= 4 || pid === process.pid) return { success: false, message: 'Cannot terminate system or current process PID.' };
  const result = windows ? await command('taskkill', ['/F', '/PID', String(pid)]) : await command('kill', ['-9', String(pid)]);
  return { success: result.ok, pid, message: `Process ${processName || ''} (PID: ${pid}) ${result.ok ? 'terminated' : 'not terminated'}: ${result.output}` };
}
export const getBlockedIps = () => [...blocked.values()];
