import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'waytrace-test-'));
process.env.WAYTRACE_DB_PATH = path.join(directory, 'test.db');
const { app } = await import('../server.js');
const db = await import('../backend/database.js');
let server, base;
before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  await new Promise(resolve => server.close(resolve));
  db.closeDb();
  fs.rmSync(directory, { recursive: true, force: true });
});
async function request(route, method = 'GET', body) {
  const response = await fetch(`${base}${route}`, { method, headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: response.status, data: await response.json() };
}

test('dashboard, scenarios, classification, evidence, report, status, and idempotent correlation', async () => {
  const page = await fetch(base);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /WayTrace/);
  const empty = await request('/api/status');
  assert.equal(empty.data.total_incidents, 0);

  for (const [name, category, domain] of [
    ['account_compromise', 'Account Takeover', 'Cross-Domain'],
    ['password_spray', 'Password Spraying', 'Authentication'],
    ['endpoint_persistence', 'Endpoint Compromise', 'Endpoint'],
    ['app_abuse', 'Application / API Abuse', 'Application'],
    ['c2', 'Command and Control', 'Network']
  ]) {
    await request('/api/clear', 'POST');
    const loaded = await request(`/api/scenarios/${name}/load`, 'POST');
    assert.equal(loaded.status, 200);
    assert.ok(loaded.data.events_count > 0);
    const incidents = (await request('/api/incidents')).data;
    const incident = incidents.find(item => item.threat_category === category);
    assert.ok(incident, `${name}: expected ${category}`);
    assert.equal(incident.domain, domain);
    if (name === 'account_compromise') {
      assert.equal(loaded.data.events_count, 9);
      assert.equal(incident.severity, 'CRITICAL');
      assert.ok(incident.risk_score >= 85);
      const detail = (await request(`/api/incidents/${incident.id}`)).data;
      assert.equal(detail.events.length, 9);
      assert.ok(detail.evidence.some(item => item.type === 'Successful Login'));
      assert.ok(detail.evidence.some(item => item.type === 'File Integrity Modification (FIM)'));
      assert.ok(detail.recommendations.some(item => item.recommendation.includes('reset credentials')));
      const report = (await request(`/api/incidents/${incident.id}/report`)).data.markdown;
      assert.match(report, /WayTrace/);
      assert.match(report, /Attack Reconstruction Timeline/);
      assert.equal((await request('/api/notifications')).data[0].level, 'CRITICAL');
      assert.equal((await request('/api/correlate', 'POST')).data.incidents_count, 0);
      assert.equal((await request('/api/incidents')).data.length, 1);
      assert.equal((await request(`/api/incidents/${incident.id}/status`, 'PATCH', { status: 'CONTAINED' })).status, 200);
      assert.equal((await request(`/api/incidents/${incident.id}`)).data.incident.is_contained, true);
    }
  }
});

test('raw ingest and webhook routes retain their response contracts', async () => {
  await request('/api/clear', 'POST');
  const invalid = await request('/api/ingest', 'POST', { raw_data: 'not json' });
  assert.equal(invalid.status, 400);
  const alert = { timestamp: '2026-09-19T03:00:00Z', event_type: 'alert', src_ip: '203.0.113.7', dest_ip: '192.168.0.2', alert: { signature: 'ET C2 Beacon', severity: 1 } };
  const ingest = await request('/api/ingest', 'POST', { raw_data: JSON.stringify(alert) });
  assert.equal(ingest.data.events_count, 1);
  const suricata = await request('/api/adapter/suricata', 'POST', alert);
  assert.equal(suricata.data.events_ingested, 1);
  const wazuh = await request('/api/adapter/wazuh', 'POST', { rule: { level: 10, groups: ['authentication_failed'] }, agent: { name: 'host' }, data: { srcip: '203.0.113.7' } });
  assert.equal(wazuh.data.events_ingested, 1);
  const csvData = "src_port,dst_port,protocol_type_TCP,label\n49152,80,True,1.0\n49153,443,True,0.0";
  const csvIngest = await request('/api/ingest', 'POST', { raw_data: csvData });
  assert.equal(csvIngest.data.events_count, 2);
  assert.equal((await request('/api/cyberguard/feed')).data.module, 'WAYTRACE_DETECTION');
  assert.equal((await request('/api/incidents/missing')).status, 404);
  assert.equal((await request('/api/scenarios/missing/load', 'POST')).status, 404);
  assert.equal((await request('/openapi.json')).data.info.title, 'WayTrace API');
  assert.equal((await request('/api/waytrace/feed')).data.module, 'WAYTRACE_DETECTION');
  assert.equal((await request('/api/ips/block', 'POST', { ip_address: 'not-an-ip' })).data.success, false);
  assert.equal((await request('/api/ips/terminate', 'POST', { pid: 0 })).data.success, false);
  const crossOrigin = await fetch(`${base}/api/status`, { headers: { Origin: 'https://example.test' } });
  assert.equal(crossOrigin.headers.get('access-control-allow-origin'), '*');
});

test('live socket routes return real host telemetry and scanner state', async () => {
  const connections = await request('/api/system/connections?limit=5');
  assert.equal(connections.status, 200);
  assert.ok(Array.isArray(connections.data));
  assert.ok(connections.data.every(item => item.remote_port > 0 && item.process_name));
  const started = await request('/api/scan/start', 'POST');
  assert.equal(started.data.status.is_scanning, true);
  const stopped = await request('/api/scan/stop', 'POST');
  assert.equal(stopped.data.status.is_scanning, false);
  const snapshot = await request('/api/scan/snapshot', 'POST');
  assert.equal(snapshot.status, 200);
  assert.ok(snapshot.data.events_count >= 0);
});
