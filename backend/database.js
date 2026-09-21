import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const dataDirectory = path.join(projectRoot, 'data');
const databasePath = process.env.WAYTRACE_DB_PATH || path.join(dataDirectory, 'waytrace.db');
mkdirSync(path.dirname(databasePath), { recursive: true });
const db = new Database(databasePath);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

const tables = [
  `CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL, domain TEXT DEFAULT 'Network', event_type TEXT NOT NULL, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protocol TEXT, domain_name TEXT, severity INTEGER DEFAULT 0, signature TEXT, flow_id TEXT, sensor_id TEXT, agent_id TEXT, agent_name TEXT, rule_id TEXT, rule_level INTEGER, user TEXT, process_name TEXT, process_path TEXT, process_cmdline TEXT, process_pid INTEGER, file_path TEXT, mitre_json TEXT, raw_json TEXT)`,
  `CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, domain TEXT DEFAULT 'Cross-Domain', status TEXT NOT NULL, severity TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence INTEGER NOT NULL, threat_category TEXT NOT NULL, indicators TEXT, affected_assets TEXT, affected_users TEXT, affected_processes TEXT, source_entities TEXT, destination_entities TEXT, mitre_tags TEXT, first_seen TEXT, last_seen TEXT, created_at TEXT, updated_at TEXT, is_contained INTEGER DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS incident_events (incident_id TEXT NOT NULL, event_id TEXT NOT NULL, relationship_type TEXT DEFAULT 'correlated', PRIMARY KEY (incident_id, event_id), FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE, FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE)`,
  `CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL, timestamp TEXT NOT NULL, description TEXT, FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE)`,
  `CREATE TABLE IF NOT EXISTS recommendations (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, category TEXT NOT NULL, priority TEXT NOT NULL, recommendation TEXT NOT NULL, status TEXT DEFAULT 'OPEN', FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE)`,
  `CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, generated_at TEXT NOT NULL, report_type TEXT DEFAULT 'INCIDENT_INVESTIGATION', content_markdown TEXT, content_html TEXT, FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE)`,
  `CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, level TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, incident_id TEXT, domain TEXT DEFAULT 'General')`
];
for (const sql of tables) db.exec(sql);

// Older databases may predate these fields. Keep their rows and add only missing columns.
for (const [table, columns] of Object.entries({
  events: { domain: "TEXT DEFAULT 'Network'", domain_name: 'TEXT', agent_id: 'TEXT', agent_name: 'TEXT', rule_id: 'TEXT', rule_level: 'INTEGER', user: 'TEXT', process_name: 'TEXT', process_path: 'TEXT', process_cmdline: 'TEXT', process_pid: 'INTEGER', file_path: 'TEXT', mitre_json: 'TEXT' },
  incidents: { domain: "TEXT DEFAULT 'Cross-Domain'", indicators: 'TEXT', affected_users: 'TEXT', affected_processes: 'TEXT', mitre_tags: 'TEXT', is_contained: 'INTEGER DEFAULT 0' }
})) {
  const existing = new Set(db.pragma(`table_info(${table})`).map(row => row.name));
  for (const [column, type] of Object.entries(columns)) if (!existing.has(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
}

const eventFields = ['timestamp', 'source', 'domain', 'event_type', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'domain_name', 'severity', 'signature', 'flow_id', 'sensor_id', 'agent_id', 'agent_name', 'rule_id', 'rule_level', 'user', 'process_name', 'process_path', 'process_cmdline', 'process_pid', 'file_path'];
const incidentFields = ['title', 'description', 'domain', 'status', 'severity', 'risk_score', 'confidence', 'threat_category', 'first_seen', 'last_seen', 'created_at', 'updated_at'];
const incidentArrays = ['indicators', 'affected_assets', 'affected_users', 'affected_processes', 'source_entities', 'destination_entities', 'mitre_tags'];
const insert = (table, fields, verb = 'INSERT OR REPLACE') => db.prepare(`${verb} INTO ${table} (${fields.join(', ')}) VALUES (${fields.map(() => '?').join(', ')})`);
const parse = (value, fallback) => { try { return value ? JSON.parse(value) : fallback; } catch { return fallback; } };
const eventFromRow = row => {
  const event = Object.fromEntries(eventFields.map(field => [field, row[field]]));
  const mitre = parse(row.mitre_json, {});
  return { event_id: row.id, ...event, mitre_tactics: mitre.tactics || [], mitre_techniques: mitre.techniques || [], raw_event: parse(row.raw_json, {}) };
};
const incidentFromRow = row => ({
  id: row.id, ...Object.fromEntries(incidentFields.map(field => [field, row[field]])),
  ...Object.fromEntries(incidentArrays.map(field => [field, parse(row[field], [])])),
  event_ids: db.prepare('SELECT event_id FROM incident_events WHERE incident_id = ?').all(row.id).map(item => item.event_id),
  is_contained: Boolean(row.is_contained)
});

const putEvent = insert('events', ['id', ...eventFields, 'mitre_json', 'raw_json']);
export const saveEvents = db.transaction(events => {
  for (const event of events) putEvent.run(event.event_id, ...eventFields.map(field => event[field] ?? null), JSON.stringify({ tactics: event.mitre_tactics || [], techniques: event.mitre_techniques || [] }), JSON.stringify(event.raw_event || {}));
});
export const getEvents = (limit = 500) => db.prepare('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?').all(limit).map(eventFromRow);
const putIncident = insert('incidents', ['id', ...incidentFields, ...incidentArrays, 'is_contained']);
const linkEvent = insert('incident_events', ['incident_id', 'event_id', 'relationship_type'], 'INSERT OR IGNORE');
export const saveIncident = db.transaction(incident => {
  putIncident.run(incident.id, ...incidentFields.map(field => incident[field] ?? null), ...incidentArrays.map(field => JSON.stringify(incident[field] || [])), Number(incident.is_contained));
  for (const id of incident.event_ids || []) linkEvent.run(incident.id, id, 'correlated');
});
export const getIncidents = () => db.prepare('SELECT * FROM incidents ORDER BY risk_score DESC, created_at DESC').all().map(incidentFromRow);
export const getIncident = id => { const row = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id); return row ? incidentFromRow(row) : null; };
export const getIncidentEvents = id => db.prepare('SELECT e.* FROM events e JOIN incident_events ie ON e.id = ie.event_id WHERE ie.incident_id = ? ORDER BY e.timestamp ASC').all(id).map(eventFromRow);
export const updateStatus = (id, status) => db.prepare('UPDATE incidents SET status = ?, updated_at = ?, is_contained = max(is_contained, ?) WHERE id = ?').run(status, new Date().toISOString(), Number(status === 'CONTAINED'), id).changes > 0;
const putEvidence = insert('evidence', ['id', 'incident_id', 'type', 'value', 'source', 'timestamp', 'description']);
export const saveEvidence = db.transaction(items => { for (const item of items) putEvidence.run(item.id, item.incident_id, item.type, item.value, item.source, item.timestamp, item.description); });
export const getEvidence = id => db.prepare('SELECT * FROM evidence WHERE incident_id = ? ORDER BY timestamp ASC').all(id);
const putRec = insert('recommendations', ['id', 'incident_id', 'category', 'priority', 'recommendation', 'status']);
export const saveRecommendations = db.transaction(items => { for (const item of items) putRec.run(item.id, item.incident_id, item.category, item.priority, item.recommendation, item.status || 'OPEN'); });
export const getRecommendations = id => db.prepare('SELECT * FROM recommendations WHERE incident_id = ? ORDER BY priority DESC').all(id);
export const replaceIncidentDetails = db.transaction(id => {
  db.prepare('DELETE FROM evidence WHERE incident_id = ?').run(id);
  db.prepare('DELETE FROM recommendations WHERE incident_id = ?').run(id);
});
export const saveReport = (id, markdown) => db.prepare('INSERT OR REPLACE INTO reports (id, incident_id, generated_at, report_type, content_markdown, content_html) VALUES (?, ?, ?, ?, ?, ?)').run(`REP-${id}`, id, new Date().toISOString(), 'INCIDENT_INVESTIGATION', markdown, '');
const putNotification = insert('notifications', ['id', 'timestamp', 'level', 'title', 'message', 'incident_id', 'domain']);
export const saveNotification = item => putNotification.run(item.id, item.timestamp, item.level, item.title, item.message, item.incident_id, item.domain);
export const getNotifications = (limit = 50) => db.prepare('SELECT * FROM notifications ORDER BY timestamp DESC LIMIT ?').all(limit);
export const clearAll = db.transaction(() => { for (const table of ['incident_events', 'evidence', 'recommendations', 'reports', 'incidents', 'events', 'notifications']) db.prepare(`DELETE FROM ${table}`).run(); });
export const countRows = table => db.prepare(`SELECT count(*) AS count FROM ${table}`).get().count;
export const closeDb = () => db.close();
