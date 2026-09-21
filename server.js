import express from 'express';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as db from './backend/database.js';
import { normalizeWazuh, normalizeSuricata, parseRaw } from './backend/normalizer.js';
import { correlate, timeline, report } from './backend/detection.js';
import { scenarios } from './backend/scenarios.js';
import { scanner, systemConnections } from './backend/scanner.js';
import { blockIp, unblockIp, terminateProcess, getBlockedIps } from './backend/ips.js';
import { openapi } from './backend/openapi.js';

const root = path.dirname(fileURLToPath(import.meta.url));
export const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(root, 'frontend')));
const error = (res, status, detail) => res.status(status).json({ detail });
const bounded = (value, fallback, max = 1000) => Number.isSafeInteger(Number(value)) ? Math.min(max, Math.max(1, Number(value))) : fallback;
const ingest = events => { db.saveEvents(events); return correlate(); };

app.get('/api/status', (_req, res) => {
  const incidents = db.getIncidents();
  res.json({ status: 'online', platform: 'WayTrace', total_events: db.getEvents(1000).length, total_incidents: incidents.length,
    open_incidents: incidents.filter(item => !['RESOLVED', 'FALSE_POSITIVE'].includes(item.status)).length,
    blocked_ips_count: getBlockedIps().length, scanner: scanner.status(), recent_notifications: db.getNotifications(3) });
});
app.post('/api/ingest', (req, res) => {
  if (typeof req.body?.raw_data !== 'string') return error(res, 400, 'raw_data must be a string.');
  const events = parseRaw(req.body.raw_data, req.body.source_hint);
  if (!events.length) return error(res, 400, 'No valid Wazuh, Suricata, or Zeek JSON events found.');
  const incidents = ingest(events);
  return res.json({ message: `Adapter processed ${events.length} events and updated ${incidents.length} incidents.`, events_count: events.length, incidents_count: incidents.length });
});
app.post('/api/adapter/wazuh', (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return error(res, 400, 'JSON alert object required.');
  const incidents = ingest([normalizeWazuh(req.body)]);
  return res.json({ status: 'accepted', events_ingested: 1, incidents_active: incidents.length });
});
app.post('/api/adapter/suricata', (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return error(res, 400, 'JSON alert object required.');
  const incidents = ingest([normalizeSuricata(req.body)]);
  return res.json({ status: 'accepted', events_ingested: 1, incidents_active: incidents.length });
});
app.get('/api/notifications', (req, res) => res.json(db.getNotifications(bounded(req.query.limit, 50))));
app.post('/api/scan/start', (_req, res) => { scanner.start(); res.json({ message: 'Live host socket scanner started.', status: scanner.status() }); });
app.post('/api/scan/stop', (_req, res) => { scanner.stop(); res.json({ message: 'Live host socket scanner stopped.', status: scanner.status() }); });
app.post('/api/scan/snapshot', async (_req, res) => {
  try {
    const events = await scanner.scanOnce(), incidents = correlate();
    res.json({ message: `Inspected active system sockets. Captured ${events.length} telemetry events.`, events_count: events.length, incidents_count: incidents.length, incidents });
  } catch (err) { error(res, 503, `Unable to inspect system connections: ${err.message}`); }
});
app.get('/api/system/connections', async (req, res) => {
  try { res.json(await systemConnections(bounded(req.query.limit, 50))); }
  catch (err) { error(res, 503, `Unable to read system connections: ${err.message}`); }
});
app.post('/api/correlate', (_req, res) => {
  const incidents = correlate();
  res.json({ message: `Correlation completed. ${incidents.length} incidents generated/updated.`, incidents_count: incidents.length, incidents });
});
app.get('/api/incidents', (_req, res) => res.json(db.getIncidents()));
app.get('/api/incidents/:id', (req, res) => {
  const incident = db.getIncident(req.params.id);
  if (!incident) return error(res, 404, 'Incident not found.');
  const events = db.getIncidentEvents(incident.id);
  return res.json({ incident, timeline: timeline(events, incident.threat_category), evidence: db.getEvidence(incident.id), recommendations: db.getRecommendations(incident.id), events });
});
app.patch('/api/incidents/:id/status', (req, res) => {
  const status = req.body?.status;
  if (!['NEW', 'TRIAGED', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'].includes(status)) return error(res, 400, 'Invalid incident status.');
  if (!db.updateStatus(req.params.id, status)) return error(res, 404, 'Incident not found.');
  return res.json({ message: `Incident status updated to ${status}.` });
});
app.get('/api/incidents/:id/report', (req, res) => {
  const incident = db.getIncident(req.params.id);
  if (!incident) return error(res, 404, 'Incident not found.');
  const markdown = report(incident, timeline(db.getIncidentEvents(incident.id), incident.threat_category), db.getEvidence(incident.id), db.getRecommendations(incident.id));
  db.saveReport(incident.id, markdown);
  return res.json({ incident_id: incident.id, report_id: `REP-${incident.id}`, markdown });
});
app.post('/api/ips/block', async (req, res) => {
  const result = await blockIp(req.body?.ip_address, req.body?.reason);
  if (req.body?.incident_id && result.success) db.updateStatus(req.body.incident_id, 'CONTAINED');
  res.json(result);
});
app.post('/api/ips/unblock', async (req, res) => res.json(await unblockIp(req.body?.ip_address)));
app.post('/api/ips/terminate', async (req, res) => {
  const result = await terminateProcess(req.body?.pid, req.body?.process_name);
  if (req.body?.incident_id && result.success) db.updateStatus(req.body.incident_id, 'CONTAINED');
  res.json(result);
});
app.get('/api/ips/blocked', (_req, res) => res.json(getBlockedIps()));
app.post('/api/scenarios/:name/load', (req, res) => {
  const make = scenarios[req.params.name];
  if (!make) return error(res, 404, `Scenario '${req.params.name}' not found.`);
  const events = parseRaw(JSON.stringify(make()));
  const incidents = ingest(events);
  return res.json({ message: `Loaded scenario '${req.params.name}'. Ingested ${events.length} events, created ${incidents.length} incidents.`, events_count: events.length, incidents });
});
const feed = (_req, res) => res.json({ module: 'WAYTRACE_DETECTION', status: 'HEALTHY', incidents: db.getIncidents(), notifications: db.getNotifications(25) });
app.get('/api/waytrace/feed', feed);
app.get('/api/cyberguard/feed', feed);
app.post('/api/clear', (_req, res) => { db.clearAll(); res.json({ message: 'All WayTrace database tables cleared.' }); });
app.get('/openapi.json', (_req, res) => res.json(openapi));
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapi, { customSiteTitle: 'WayTrace API Docs' }));
app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && 'body' in err) return error(res, 400, 'Invalid JSON request body.');
  console.error(err);
  return error(res, 500, 'Internal server error.');
});

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const host = process.env.HOST || '127.0.0.1', port = Number(process.env.PORT || 8000);
  const server = app.listen(port, host, () => console.log(`WayTrace running at http://${host}:${port}`));
  const shutdown = () => { scanner.stop(); server.close(() => { db.closeDb(); process.exit(0); }); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
