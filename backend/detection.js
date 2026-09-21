import { randomUUID } from 'node:crypto';
import * as db from './database.js';

const id = prefix => `${prefix}-${randomUUID().slice(0, 6).toUpperCase()}`;
const unique = values => [...new Set(values.filter(Boolean))];
const includesAny = (value, words) => words.some(word => String(value || '').toLowerCase().includes(word));

export function classify(events) {
  const auth = events.filter(e => e.domain === 'Authentication' || ['auth_failure', 'auth_success'].includes(e.event_type));
  const endpoint = events.filter(e => e.domain === 'Endpoint' || ['process_create', 'fim_modification'].includes(e.event_type));
  const network = events.filter(e => e.domain === 'Network' || ['suricata', 'zeek'].includes(e.source));
  const app = events.filter(e => e.domain === 'Application' || ['app_auth_failure', 'app_activity'].includes(e.event_type));
  const tags = unique(events.flatMap(e => [...(e.mitre_tactics || []), ...(e.mitre_techniques || [])]));
  const indicators = [];
  const exploit = network.some(e => e.source === 'suricata' && includesAny(e.signature, ['exploit', 'cve', 'injection', 'overflow']));
  if (exploit) indicators.push('suricata_network_exploit');
  const failures = auth.filter(e => e.event_type === 'auth_failure');
  if (failures.length >= 2) indicators.push(`multiple_failed_logins (${failures.length} attempts)`);
  const success = auth.some(e => e.event_type === 'auth_success');
  if (success) indicators.push(failures.length >= 2 ? 'successful_login_after_failures' : 'successful_login');
  const fim = endpoint.some(e => e.event_type === 'fim_modification' || e.file_path);
  if (fim) indicators.push('unauthorized_file_modification_fim');
  const process = endpoint.some(e => e.event_type === 'process_create' || includesAny(e.process_name, ['powershell', 'cmd', 'certutil', 'mshta', 'payload']));
  if (process) indicators.push('suspicious_process_execution');
  const host = events[0]?.agent_name || events[0]?.dst_ip || 'target-machine';
  const actor = events[0]?.src_ip || 'external attacker';
  const result = (domain, category, title, description, extraTags = []) => ({ domain, threat_category: category, title, description, indicators, mitre_tags: unique([...tags, ...extraTags]) });

  if ((exploit || failures.length >= 2) && success && (process || fim)) return result('Cross-Domain', 'Account Takeover', `Possible Account Compromise and Endpoint Intrusion on ${host}`, `Correlated multi-sensor detection: Threat actor at ${actor} attempted exploitation, performed credential attacks, achieved successful authentication, and executed suspicious endpoint modifications.`, ['T1078 (Valid Accounts)', 'T1059 (Command and Scripting)', 'T1110 (Brute Force)']);
  if (failures.length >= 4) {
    const users = unique(failures.map(e => e.user));
    if (users.length >= 3) {
      indicators.push('password_spraying_multiple_accounts');
      return result('Authentication', 'Password Spraying', `Password Spraying Attack Detected from ${actor}`, `Authentication telemetry recorded ${failures.length} failed login attempts distributed across ${users.length} distinct user accounts (${users.slice(0, 3).join(', ')}).`, ['T1110.003 (Password Spraying)']);
    }
    return result('Authentication', 'Brute Force', `Credential Brute Force Attack targeting '${users[0] || 'target account'}'`, `High-frequency failed logon events (${failures.length} attempts) originating from ${actor}.`, ['T1110 (Brute Force)']);
  }
  if (fim && process) return result('Endpoint', 'Endpoint Compromise', `Endpoint Tampering & Persistence Activity on ${host}`, 'Host monitoring detected suspicious process execution coupled with unauthorized file modification in system directories.', ['T1547 (Persistence)', 'T1059 (Scripting)']);
  if (fim) return result('Endpoint', 'Unauthorized File Modification (FIM)', `Critical File Integrity Violation on ${host}`, 'Wazuh FIM detected unauthorized modification or deletion of critical system binaries or configuration files.', ['T1565 (Data Manipulation - FIM)']);
  if (process) return result('Endpoint', 'Suspicious Process Execution', `Suspicious Process Execution Detected on ${host}`, 'Wazuh Sysmon captured administrative or script host execution running unusual command lines or unapproved parameters.', ['T1059 (Command and Scripting Interpreter)']);
  if (app.filter(e => e.event_type === 'app_auth_failure').length >= 3) {
    indicators.push('application_authorization_failures');
    return result('Application', 'Application / API Abuse', `API / Web Application Abuse targeting ${host}`, `Spike in HTTP 401/403 authorization failures detected from ${actor} indicating possible parameter fuzzing or credential stuffing.`, ['T1078 (Valid Accounts / API Abuse)']);
  }
  const signatures = network.map(e => e.signature || '').join(' ').toLowerCase();
  if (includesAny(signatures, ['c2', 'beacon', 'command and control', 'trojan'])) return result('Network', 'Command and Control', `Command and Control (C2) Communication by ${host}`, `Network IDS matched periodic beaconing and suspicious TLS sessions communicating with ${actor}.`, ['T1071 (Application Layer Protocol - C2)']);
  if (includesAny(signatures, ['scan', 'nmap', 'port scan'])) return result('Network', 'Scanning', `Network Port Reconnaissance / Scanning by ${actor}`, `Suricata and live sensors detected systematic port scanning targeting ${host}.`, ['T1046 (Network Service Discovery)']);
  return result(events[0]?.domain || 'Cross-Domain', 'Unknown', `Suspicious Security Event on ${host}`, `Correlated security telemetry from ${actor} requires analyst investigation.`);
}

export function score(events, domain) {
  if (!events.length) return { risk_score: 0, confidence: 0, severity: 'LOW' };
  const domains = new Set(events.map(e => e.domain));
  const types = new Set(events.map(e => e.event_type));
  const sources = new Set(events.map(e => e.source));
  const detection = Math.min(40, Math.trunc(Math.max(...events.map(e => e.severity || 0)) * 4));
  const domainScore = domain === 'Cross-Domain' || domains.size >= 3 ? 30 : domains.size >= 2 ? 20 : 10;
  let impact = 0;
  if (types.has('auth_failure') && types.has('auth_success')) impact += 10;
  if (types.has('fim_modification') || types.has('process_create')) impact += 10;
  if (events.some(e => includesAny(e.signature, ['c2', 'beacon', 'trojan', 'cobalt', 'exploit']))) impact = Math.min(20, impact + 10);
  const risk_score = Math.min(100, Math.max(10, detection + domainScore + impact + Math.min(10, events.length * 2)));
  const severity = risk_score <= 20 ? 'LOW' : risk_score <= 40 ? 'MODERATE' : risk_score <= 60 ? 'MEDIUM' : risk_score <= 80 ? 'HIGH' : 'CRITICAL';
  let confidence = 40;
  if (sources.size >= 2 || domain === 'Cross-Domain' || sources.has('suricata')) confidence += 30;
  if (domains.size >= 2 || domain === 'Cross-Domain' || types.size >= 3) confidence += 15;
  else if (types.size >= 2) confidence += 10;
  if (types.has('auth_failure') && types.has('auth_success')) confidence += 10;
  return { risk_score, confidence: Math.min(98, Math.max(30, confidence)), severity };
}

function extractEvidence(events, incidentId) {
  return events.flatMap(ev => {
    const base = { id: id('EVD'), incident_id: incidentId, timestamp: ev.timestamp };
    if (ev.source === 'suricata' || ev.event_type === 'suricata_alert') return [{ ...base, type: 'IDS Exploit Alert', value: ev.signature || 'Network Exploit Match', source: 'Suricata', description: `Rule match severity ${ev.severity}/10 from ${ev.src_ip} targeting port ${ev.dst_port || 'N/A'}` }];
    if (ev.event_type === 'auth_failure') return [{ ...base, type: 'Authentication Failure', value: `User: ${ev.user || 'unknown'}`, source: 'Wazuh Auth', description: `Failed authentication attempt from ${ev.src_ip || 'unknown IP'}` }];
    if (ev.event_type === 'auth_success') return [{ ...base, type: 'Successful Login', value: `User: ${ev.user || 'unknown'}`, source: 'Wazuh Auth', description: `Subsequent successful login session established by ${ev.src_ip || 'unknown IP'}` }];
    if (ev.event_type === 'process_create' || ev.process_name) return [{ ...base, type: 'Endpoint Process Execution', value: ev.process_cmdline || ev.process_name || 'Unknown process', source: 'Wazuh Sysmon', description: `Process ${ev.process_name} (PID: ${ev.process_pid || 'N/A'}) launched on ${ev.agent_name || 'host'}` }];
    if (ev.event_type === 'fim_modification' || ev.file_path) return [{ ...base, type: 'File Integrity Modification (FIM)', value: ev.file_path || 'Critical system file', source: 'Wazuh Syscheck', description: 'Unauthorized file alteration or creation detected in monitored directory' }];
    return [];
  });
}

function recommendations(incident, events) {
  const items = [];
  const add = (category, priority, recommendation) => items.push({ id: id('REC'), incident_id: incident.id, category, priority, recommendation, status: 'OPEN' });
  const assets = incident.affected_assets.join(', ') || 'the affected endpoint';
  const users = incident.affected_users.join(', ') || 'the affected user account';
  const peers = incident.destination_entities.join(', ') || 'the threat actor address';
  if (['Account Takeover', 'Authentication Attack', 'Brute Force'].includes(incident.threat_category)) {
    add('Immediate', 'CRITICAL', `Terminate active sessions and immediately reset credentials for ${users}.`);
    add('Immediate', 'HIGH', `Isolate endpoint (${assets}) from the corporate LAN to contain potential lateral movement.`);
    add('Immediate', 'HIGH', `Block attacker IP (${peers}) across all perimeter and host firewalls via Active Response.`);
    add('Short-Term', 'MEDIUM', `Investigate source IP ${peers} for prior failed authentication attempts across other internal servers.`);
    add('Long-Term', 'LOW', 'Enforce Multi-Factor Authentication (MFA) and account lockout thresholds after 5 consecutive failures.');
  } else if (['Endpoint Compromise', 'Suspicious Process Execution', 'Unauthorized File Modification (FIM)'].includes(incident.threat_category)) {
    add('Immediate', 'CRITICAL', `Terminate the suspicious process tree and quarantine unauthorized executables on ${assets}.`);
    add('Immediate', 'HIGH', 'Inspect modified system files detected by Wazuh FIM and restore verified copies from clean backups.');
    add('Short-Term', 'MEDIUM', 'Inspect Registry Run keys, Startup folders, and Scheduled Tasks for persistence hooks.');
    add('Long-Term', 'LOW', 'Implement AppLocker / Application Whitelisting to prevent unauthorized binaries executing in Temp directories.');
  } else {
    add('Immediate', 'HIGH', `Block all ingress and egress traffic to ${peers} at the host firewall.`);
    add('Short-Term', 'MEDIUM', 'Review Suricata sensor rules and search Zeek telemetry for any other internal hosts beaconing to the same infrastructure.');
    add('Long-Term', 'LOW', 'Implement network micro-segmentation and egress traffic filtering.');
  }
  return items;
}

export function correlate(windowSeconds = 600) {
  const events = db.getEvents(1000).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const ipToAgent = new Map();
  for (const ev of events) if (ev.agent_name) for (const ip of [ev.src_ip, ev.dst_ip]) if (ip) ipToAgent.set(ip, ev.agent_name);
  const groups = new Map();
  for (const ev of events) {
    const host = ev.agent_name || ipToAgent.get(ev.dst_ip) || ipToAgent.get(ev.src_ip) || ev.dst_ip || ev.src_ip || 'local-system';
    const peer = ev.src_ip && ev.src_ip !== ev.dst_ip && ev.src_ip !== '127.0.0.1' ? ev.src_ip : ev.dst_ip || 'external';
    const key = `${host}::${peer}`;
    const clusters = groups.get(key) || [];
    const last = clusters.at(-1);
    if (!last || new Date(ev.timestamp) - new Date(last.at(-1).timestamp) > windowSeconds * 1000) clusters.push([ev]);
    else last.push(ev);
    groups.set(key, clusters);
  }
  const existing = db.getIncidents();
  const changed = [];
  for (const clusters of groups.values()) for (const group of clusters) {
    if (!group.some(e => e.severity >= 4 || ['alert', 'suricata_alert', 'auth_failure', 'fim_modification', 'process_create'].includes(e.event_type)) && group.length < 3) continue;
    const currentIds = group.map(e => e.event_id);
    const match = existing.find(inc => inc.event_ids.some(id => currentIds.includes(id)));
    if (match && currentIds.every(id => match.event_ids.includes(id))) continue;
    const classification = classify(group);
    const scoring = score(group, classification.domain);
    const affected_assets = unique(group.flatMap(e => [e.agent_name, ...[e.src_ip, e.dst_ip].filter(ip => /^(192\.168\.|10\.|172\.|127\.)/.test(ip || ''))]));
    if (!affected_assets.length) affected_assets.push(...unique(group.map(e => e.dst_ip || 'local-system')));
    const peers = unique(group.flatMap(e => [e.src_ip, e.dst_ip]).filter(ip => !affected_assets.includes(ip)));
    const now = new Date().toISOString();
    const incident = {
      id: match?.id || id('INC'), ...classification, ...scoring,
      status: match?.status || 'NEW', affected_assets, affected_users: unique(group.map(e => e.user)),
      affected_processes: unique(group.map(e => e.process_name)), source_entities: peers, destination_entities: peers,
      first_seen: group[0].timestamp, last_seen: group.at(-1).timestamp,
      created_at: match?.created_at || now, updated_at: now, event_ids: currentIds, is_contained: match?.is_contained || false
    };
    db.saveIncident(incident);
    if (match) {
      // Refresh derived records when a cluster gains events.
      db.replaceIncidentDetails(incident.id);
    }
    db.saveEvidence(extractEvidence(group, incident.id));
    db.saveRecommendations(recommendations(incident, group));
    if (incident.risk_score >= 40 && !match) db.saveNotification({
      id: id('NOTIF'), timestamp: now, level: incident.risk_score >= 80 ? 'CRITICAL' : incident.risk_score >= 60 ? 'WARNING' : 'INFO',
      title: incident.title, message: `[${incident.domain.toUpperCase()}] Risk ${incident.risk_score}/100. ${incident.description}`,
      incident_id: incident.id, domain: incident.domain
    });
    changed.push(incident);
  }
  return changed;
}

export function timeline(events, category) {
  if (!events.length) return [];
  const sorted = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const items = sorted.map(ev => {
    let stage = 'Observation', description = ev.signature || `${ev.protocol} traffic ${ev.src_ip} -> ${ev.dst_ip}`;
    if (['alert', 'suricata_alert'].includes(ev.event_type) || ev.source === 'suricata') { stage = 'Network Exploit / IDS Detection'; description = `Suricata Alert: ${ev.signature} from ${ev.src_ip}`; }
    else if (ev.event_type === 'auth_failure') { stage = 'Authentication Failure'; description = `Logon failed for account '${ev.user || 'unknown'}' from IP ${ev.src_ip || 'unknown'}`; }
    else if (ev.event_type === 'auth_success') { stage = 'Successful Logon'; description = `Authentication succeeded for account '${ev.user}' from IP ${ev.src_ip}`; }
    else if (ev.event_type === 'process_create' || ev.process_name) { stage = 'Endpoint Execution'; description = `Process spawned: ${ev.process_name} (Command: ${ev.process_cmdline || 'N/A'})`; }
    else if (ev.event_type === 'fim_modification' || ev.file_path) { stage = 'File Modification (FIM)'; description = `File modified or created: ${ev.file_path}`; }
    else if (ev.event_type === 'app_auth_failure') { stage = 'Application Authorization Failure'; description = `HTTP 401/403 authorization failure from ${ev.src_ip}`; }
    else if (ev.event_type === 'dns') { stage = 'Name Resolution'; description = `DNS Query resolved: ${ev.domain_name || 'unknown host'}`; }
    else if (ev.event_type === 'ssl') { stage = 'Encrypted Channel'; description = `TLS handshake established to ${ev.domain_name || ev.dst_ip}`; }
    else if (ev.event_type === 'http') { stage = 'Web Traffic'; description = `HTTP request: ${ev.signature}`; }
    else if (ev.event_type === 'conn') { stage = 'Network Flow'; description = `Connection ${ev.src_ip} -> ${ev.dst_ip}:${ev.dst_port}`; }
    return { timestamp: ev.timestamp, stage, description, source: `${ev.source.toUpperCase()} (${ev.event_id})${ev.agent_name ? ` on ${ev.agent_name}` : ''}`, is_inferred: false };
  });
  const infer = (ev, stage, description) => items.push({ timestamp: ev.timestamp, stage, description, source: 'WayTrace Intelligence Engine', is_inferred: true });
  const failures = sorted.filter(e => e.event_type === 'auth_failure');
  const successes = sorted.filter(e => e.event_type === 'auth_success');
  const conns = sorted.filter(e => e.event_type === 'conn');
  if (failures.length && successes.length) infer(successes.at(-1), 'Account Compromise Confirmed (Inferred)', 'Threat actor successfully authenticated following repeated credential attempts');
  if (successes.length && sorted.some(e => ['fim_modification', 'process_create'].includes(e.event_type))) infer(sorted.at(-1), 'Post-Exploitation Activity (Inferred)', 'Compromised credentials leveraged to alter endpoint files or spawn untrusted binaries');
  if (conns.length >= 2) infer(conns.at(-1), 'Suspicious Persistence (Inferred)', `Repetitive communication pattern detected (${conns.length} connections)`);
  if (sorted.some(e => ['suricata', 'zeek'].includes(e.source) || ['alert', 'suricata_alert'].includes(e.event_type)) && sorted.some(e => ['conn', 'dns'].includes(e.event_type))) infer(sorted.at(-1), 'Threat Assessment (Inferred)', `Potential active ${category} session confirmed by multi-sensor telemetry`);
  return items.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export function report(incident, items, evidence, recs) {
  const lines = items.map(item => `- **${item.timestamp}** | [${item.source}] **${item.stage}**: ${item.description}${item.is_inferred ? ' *(Inferred)*' : ''}`);
  const proofs = evidence.map(item => `- **[${item.source.toUpperCase()}]** ${item.type.toUpperCase()}: \`${item.value}\` - ${item.description}`);
  const byCategory = category => recs.filter(item => item.category === category).map(item => `- ${item.recommendation}`).join('\n') || '- No actions.';
  return `# SECURITY INCIDENT INVESTIGATION REPORT

**Report Generated:** ${new Date().toISOString()}  
**Platform:** WayTrace  

---

## 1. Executive Summary

| Field | Details |
|---|---|
| **Incident ID** | \`${incident.id}\` |
| **Title** | ${incident.title} |
| **Threat Category** | ${incident.threat_category} |
| **Status** | **${incident.status}** |
| **Severity** | **${incident.severity}** |
| **Risk Score** | **${incident.risk_score} / 100** |
| **Detection Confidence** | **${incident.confidence}%** |
| **Affected Assets** | ${incident.affected_assets.join(', ') || 'N/A'} |
| **Source Entities** | ${incident.source_entities.join(', ') || 'N/A'} |
| **Destination Entities** | ${incident.destination_entities.join(', ') || 'N/A'} |
| **First Observed** | ${incident.first_seen} |
| **Last Observed** | ${incident.last_seen} |

### Description
${incident.description}

---

## 2. Attack Reconstruction Timeline

${lines.join('\n') || 'No timeline events recorded.'}

---

## 3. Corroborated Evidence Store

${proofs.join('\n') || 'No evidence recorded.'}

---

## 4. Recommended Action Plan

### Immediate Actions
${byCategory('Immediate')}

### Short-Term Investigation
${byCategory('Short-Term')}

### Long-Term Hardening
${byCategory('Long-Term')}

---
*Report automatically compiled by WayTrace.*`;
}
