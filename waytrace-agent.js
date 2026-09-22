import si from 'systeminformation';

// WayTrace Central Server URL
const SERVER_URL = process.env.WAYTRACE_SERVER_URL || 'http://127.0.0.1:8000';
const INTERVAL_MS = 3000;

console.log('----------------------------------------------------');
console.log('   🛡️  WayTrace Remote Agent (Live Socket Streamer)  ');
console.log('----------------------------------------------------');
console.log(`Connecting live network socket stream to: ${SERVER_URL}`);

async function getLiveSockets() {
  try {
    const [connections, processes] = await Promise.all([
      si.networkConnections(),
      si.processes()
    ]);
    const processMap = new Map(processes.list.map(p => [p.pid, p.name]));

    return connections
      .filter(c => c.peerAddress && !['*', '0.0.0.0', '::'].includes(c.peerAddress) && Number(c.peerPort) > 0)
      .map(c => ({
        timestamp: new Date().toISOString(),
        source: 'waytrace_agent',
        event_type: 'conn',
        src_ip: c.localAddress || '127.0.0.1',
        src_port: Number(c.localPort) || 0,
        dst_ip: c.peerAddress,
        dst_port: Number(c.peerPort) || 0,
        protocol: String(c.protocol || 'TCP').toUpperCase(),
        severity: 1,
        signature: `Live connection by ${c.process || processMap.get(Number(c.pid)) || 'Unknown'} -> ${c.peerAddress}:${c.peerPort}`,
        raw_event: {
          process_name: c.process || processMap.get(Number(c.pid)) || 'Unknown',
          pid: Number(c.pid) || 0,
          status: c.state || 'ESTABLISHED'
        }
      }));
  } catch (err) {
    console.error('Error reading host sockets:', err.message);
    return [];
  }
}

async function sendTelemetry() {
  const events = await getLiveSockets();
  if (!events.length) return;

  try {
    const response = await fetch(`${SERVER_URL}/api/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_data: JSON.stringify(events) })
    });
    const data = await response.json();
    console.log(`[${new Date().toLocaleTimeString()}] Sent ${events.length} live connections -> ${data.message || 'Accepted'}`);
  } catch (err) {
    console.error(`[${new Date().toLocaleTimeString()}] Failed to stream telemetry to ${SERVER_URL}:`, err.message);
  }
}

// Start live streaming interval
sendTelemetry();
setInterval(sendTelemetry, INTERVAL_MS);
