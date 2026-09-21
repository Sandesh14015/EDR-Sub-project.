# WayTrace Architecture

WayTrace is a Node.js and Express detection console. It accepts Wazuh 4.x alerts,
Suricata EVE records, and Zeek JSON records, normalizes them to one event shape,
correlates events into incidents, and stores evidence and recommendations in SQLite.

```text
Wazuh / Suricata / Zeek / host sockets
                |
          normalizer.js
                |
           database.js
                |
           detection.js
     classification + risk + evidence
                |
       Express API + dashboard
                |
      analyst status and response
```

## Components

- `server.js`: Express routes, static dashboard, OpenAPI UI, and API validation.
- `backend/normalizer.js`: Wazuh, Suricata, and Zeek parsing.
- `backend/detection.js`: clustering, classification, scoring, evidence,
  recommendations, timelines, and Markdown reports.
- `backend/database.js`: SQLite schema and persistence. The default file is
  `data/waytrace.db`; set `WAYTRACE_DB_PATH` to use another location.
- `backend/scanner.js`: active host sockets and process names from
  `systeminformation`; periodic scans run every three seconds after starting.
- `backend/ips.js`: firewall blocking and process termination with argument-safe
  OS command execution. The operating system may require administrator rights.
- `backend/scenarios.js`: demo attack records for five dashboard scenarios.
- `frontend/index.html`: the plain HTML, CSS, and JavaScript console.

The API keeps the original route names where integrations depend on them. The
parent feed is available at `/api/waytrace/feed`, with `/api/cyberguard/feed`
retained as a compatibility alias. Generated incidents reuse the same ID when
new matching events arrive, and correlation groups events by peer and time.
