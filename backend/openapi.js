const json = { content: { 'application/json': { schema: { type: 'object' } } } };
const ok = { 200: { description: 'Successful response', ...json } };
const routes = [
  ['get', '/api/status', 'System status'],
  ['post', '/api/ingest', 'Ingest newline-delimited or array JSON', { raw_data: 'string', source_hint: 'string' }],
  ['post', '/api/adapter/wazuh', 'Ingest one Wazuh alert'],
  ['post', '/api/adapter/suricata', 'Ingest one Suricata EVE alert'],
  ['get', '/api/notifications', 'Recent notifications'],
  ['post', '/api/scan/start', 'Start the live host scanner'],
  ['post', '/api/scan/stop', 'Stop the live host scanner'],
  ['post', '/api/scan/snapshot', 'Scan active sockets once'],
  ['get', '/api/system/connections', 'Active remote socket connections'],
  ['post', '/api/correlate', 'Correlate stored events'],
  ['get', '/api/incidents', 'List incidents'],
  ['get', '/api/incidents/{id}', 'Incident detail'],
  ['patch', '/api/incidents/{id}/status', 'Update incident status', { status: 'string' }],
  ['get', '/api/incidents/{id}/report', 'Generate Markdown report'],
  ['post', '/api/ips/block', 'Block an IP at the host firewall', { ip_address: 'string', incident_id: 'string', reason: 'string' }],
  ['post', '/api/ips/unblock', 'Remove a host firewall block', { ip_address: 'string' }],
  ['post', '/api/ips/terminate', 'Terminate a process', { pid: 'integer', process_name: 'string', incident_id: 'string' }],
  ['get', '/api/ips/blocked', 'Blocked IPs in this session'],
  ['post', '/api/scenarios/{name}/load', 'Load a demo scenario'],
  ['get', '/api/waytrace/feed', 'WayTrace incident feed'],
  ['get', '/api/cyberguard/feed', 'Legacy feed path'],
  ['post', '/api/clear', 'Clear stored telemetry and incidents']
];
const paths = {};
for (const [method, route, summary, fields] of routes) {
  const parameters = [...route.matchAll(/\{(\w+)\}/g)].map(([, name]) => ({ name, in: 'path', required: true, schema: { type: 'string' } }));
  paths[route] ||= {};
  paths[route][method] = { summary, responses: ok, ...(parameters.length ? { parameters } : {}), ...(fields ? { requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: Object.fromEntries(Object.entries(fields).map(([name, type]) => [name, { type }])) } } } } } : {}) };
}
export const openapi = { openapi: '3.0.3', info: { title: 'WayTrace API', version: '1.0.0', description: 'Wazuh, Suricata, Zeek, incident correlation, live scanning, and active response.' }, paths };
