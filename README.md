# WayTrace

WayTrace is an endpoint and network detection console for Wazuh, Suricata, and
Zeek telemetry. It combines normalized events into incidents with evidence,
risk and confidence scores, investigation timelines, recommendations, reports,
live host connection scanning, and active response.

## Stack

- Frontend: plain HTML, CSS, and JavaScript served by Express. No build step is required.
- Backend: Node.js 20+ and Express 5.
- Storage: SQLite via `better-sqlite3`.
- Host telemetry: `systeminformation`.
- Tests: Node's built-in test runner.

## Run

```powershell
npm install
npm start
```

Open the dashboard at http://127.0.0.1:8000 and interactive API docs at
http://127.0.0.1:8000/docs. For development, use `npm run dev`. Set `PORT`,
`HOST`, or `WAYTRACE_DB_PATH` as needed. Runtime SQLite files are created in
`data/` and are excluded from version control.

## Test

```powershell
npm test
```

The tests use a temporary SQLite database. The dashboard's scenario buttons
exercise account compromise, password spraying, endpoint persistence,
application abuse, and command and control activity.

## Ingest

Send newline-delimited JSON or a JSON array to `POST /api/ingest` as
`{"raw_data":"..."}`. Direct Wazuh and Suricata webhooks are available at
`POST /api/adapter/wazuh` and `POST /api/adapter/suricata`.

The live scanner reads the host's visible sockets. Operating system permissions
can limit process details and firewall response. Blocking or terminating a
process is performed only when the respective API command is invoked.

See [ARCHITECTURE.md](ARCHITECTURE.md) for module and data flow details.
