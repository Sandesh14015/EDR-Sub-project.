import { randomUUID } from 'node:crypto';

const id = prefix => `${prefix}-${randomUUID().slice(0, 8).toUpperCase()}`;
export const timestamp = value => {
  if (!value) return new Date().toISOString();
  if (typeof value === 'number' || /^\d+(\.\d+)?$/.test(String(value))) {
    const date = new Date(Number(value) * 1000);
    return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
};
const numberOrNull = value => value === undefined || value === null || value === '' || Number.isNaN(Number(value)) ? null : Number(value);
const list = value => value == null ? [] : Array.isArray(value) ? value : [value];

export function normalizeWazuh(raw) {
  const rule = raw.rule || {}, agent = raw.agent || {}, data = raw.data || {}, syscheck = raw.syscheck || {};
  const win = data.win || {}, eventdata = win.eventdata || {};
  const groups = list(rule.groups).map(group => String(group).toLowerCase());
  const level = Number(rule.level ?? 3);
  let severity = level >= 13 ? 10 : level >= 10 ? 8 : level >= 7 ? 6 : level >= 4 ? 4 : 2;
  let signature = rule.description || 'Wazuh Security Alert';
  let domain = 'Endpoint', event_type = 'host_alert';
  let src_ip = data.srcip || eventdata.ipAddress || raw.src_ip || null;
  let dst_ip = data.dstip || agent.ip || raw.dest_ip || raw.dst_ip || null;
  let dst_port = numberOrNull(data.dstport);
  const process_name = eventdata.processName || eventdata.image || null;
  const file_path = syscheck.path || eventdata.targetFilename || null;
  if (data.suricata) {
    domain = 'Network'; event_type = 'suricata_alert';
    signature = `Suricata via Wazuh: ${data.suricata.alert?.signature || signature}`;
    src_ip = data.suricata.src_ip || src_ip;
    dst_ip = data.suricata.dest_ip || dst_ip;
    dst_port = numberOrNull(data.suricata.dest_port) || dst_port;
  } else if (['authentication_failed', 'authentication_success', 'logon_failed', 'sshd', 'pam', 'windows_auth'].some(group => groups.includes(group))) {
    domain = 'Authentication';
    event_type = groups.some(group => group.includes('success')) || signature.toLowerCase().includes('success') ? 'auth_success' : 'auth_failure';
    if (event_type === 'auth_failure') severity = Math.max(severity, 5);
  } else if (Object.keys(syscheck).length || groups.includes('syscheck')) {
    domain = 'Endpoint'; event_type = 'fim_modification';
    signature = `FIM Alert: File modified at ${file_path || 'critical system path'}`;
    severity = Math.max(severity, 7);
  } else if (groups.includes('sysmon_event1') || groups.includes('process_creation')) {
    domain = 'Endpoint'; event_type = 'process_create';
    if (process_name && ['powershell', 'cmd', 'certutil', 'mshta', 'rundll32'].some(name => process_name.toLowerCase().includes(name))) severity = Math.max(severity, 8);
  } else if (['web', 'apache', 'nginx', 'accesslog', 'api'].some(group => groups.includes(group))) {
    domain = 'Application'; event_type = /401|403/.test(signature) ? 'app_auth_failure' : 'app_activity';
    if (event_type === 'app_auth_failure') severity = Math.max(severity, 6);
  } else if (['firewall', 'ids', 'suricata', 'scan'].some(group => groups.includes(group))) {
    domain = 'Network'; event_type = 'network_alert';
  }
  return {
    event_id: id('WZH'), timestamp: timestamp(raw.timestamp), source: 'wazuh', domain, event_type,
    src_ip, dst_ip, dst_port, severity, signature,
    agent_id: String(agent.id ?? ''), agent_name: agent.name || 'local-system', rule_id: String(rule.id ?? '0'), rule_level: level,
    user: data.srcuser || data.dstuser || eventdata.targetUserName || eventdata.subjectUserName || raw.user || null,
    process_name, process_cmdline: eventdata.commandLine || null, process_pid: numberOrNull(eventdata.processId), file_path,
    mitre_tactics: list(rule.mitre?.tactic), mitre_techniques: list(rule.mitre?.technique || rule.mitre?.id),
    sensor_id: 'wazuh-server', protocol: 'TCP', raw_event: raw
  };
}

export function normalizeSuricata(raw) {
  const alert = raw.alert || {};
  const severity = raw.alert ? ({ 1: 9, 2: 6, 3: 4 }[Number(alert.severity ?? 3)] ?? 2) : 3;
  return {
    event_id: id('SURI'), timestamp: timestamp(raw.timestamp), source: 'suricata', domain: 'Network', event_type: 'suricata_alert',
    src_ip: raw.src_ip || null, src_port: numberOrNull(raw.src_port), dst_ip: raw.dest_ip || raw.dst_ip || null,
    dst_port: numberOrNull(raw.dest_port ?? raw.dst_port), protocol: String(raw.proto || 'TCP').toUpperCase(),
    domain_name: raw.dns?.rrname || raw.dns?.query || raw.tls?.sni || null,
    severity, signature: alert.signature || 'Suricata Network Alert', flow_id: raw.flow_id == null ? null : String(raw.flow_id),
    sensor_id: 'suricata-sensor', agent_id: raw.agent?.id == null ? null : String(raw.agent.id), agent_name: raw.agent?.name || null,
    mitre_tactics: [], mitre_techniques: list(raw.metadata?.mitre_technique_id), raw_event: raw
  };
}

export function normalizeZeek(raw) {
  const src_ip = raw['id.orig_h'] || raw.orig_h || raw.src_ip || null;
  const dst_ip = raw['id.resp_h'] || raw.resp_h || raw.dst_ip || null;
  const dst_port = numberOrNull(raw['id.resp_p'] ?? raw.resp_p ?? raw.dst_port);
  let event_type = 'conn', domain_name = raw.query || raw.server_name || raw.host || null;
  let signature = `Zeek connection ${src_ip} -> ${dst_ip}:${dst_port}`;
  if ('query' in raw || raw.service === 'dns') { event_type = 'dns'; signature = `DNS Query: ${domain_name}`; }
  else if ('server_name' in raw || raw.service === 'ssl') { event_type = 'ssl'; signature = `TLS/SSL Session to ${domain_name || dst_ip}`; }
  return {
    event_id: id('ZEEK'), timestamp: timestamp(raw.ts || raw.timestamp), source: 'zeek', domain: 'Network', event_type,
    src_ip, src_port: numberOrNull(raw['id.orig_p'] ?? raw.orig_p ?? raw.src_port), dst_ip, dst_port,
    protocol: String(raw.proto || 'TCP').toUpperCase(), domain_name, severity: 1, signature, flow_id: raw.uid || null,
    sensor_id: 'zeek-sensor', mitre_tactics: [], mitre_techniques: [], raw_event: raw
  };
}

function normalizeItem(item, hint) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  if (hint === 'wazuh' || 'rule' in item || ('agent' in item && !('alert' in item) && !('event_type' in item))) return normalizeWazuh(item);
  if (hint === 'suricata' || 'alert' in item || 'event_type' in item || 'dest_ip' in item) return normalizeSuricata(item);
  return normalizeZeek(item);
}
export function parseRaw(text, hint) {
  if (typeof text !== 'string') return [];
  const trimmed = text.trim();
  if (trimmed.startsWith('[')) {
    try { const value = JSON.parse(trimmed); return Array.isArray(value) ? value.map(item => normalizeItem(item, hint)).filter(Boolean) : []; } catch { return []; }
  }
  return trimmed.split(/\r?\n/).flatMap(line => {
    if (!line.trim() || line.trim().startsWith('#')) return [];
    try { const value = normalizeItem(JSON.parse(line), hint); return value ? [value] : []; } catch { return []; }
  });
}
