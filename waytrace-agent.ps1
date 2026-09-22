# 🛡️ WayTrace 1-Click Remote Windows Agent (Zero Installation Required)
# Automatically captures live Windows sockets and streams them to your central WayTrace server

Param(
    [string]$ServerUrl = "https://waytrace.yourdomain.com"
)

Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "   🛡️  WayTrace Remote Windows Agent (Live Streamer)    " -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Target Central Server: $ServerUrl" -ForegroundColor Yellow

$IntervalSeconds = 3

while ($true) {
    try {
        $connections = Get-NetTCPConnection -State Established,SynSent -ErrorAction SilentlyContinue | Where-Options { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }
        $events = @()

        foreach ($conn in $connections) {
            $procName = "Unknown"
            try { $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}

            $events += @{
                timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                source = "waytrace_remote_windows_agent"
                event_type = "conn"
                src_ip = $conn.LocalAddress
                src_port = [int]$conn.LocalPort
                dst_ip = $conn.RemoteAddress
                dst_port = [int]$conn.RemotePort
                protocol = "TCP"
                severity = 1
                signature = "Live connection by $procName -> $($conn.RemoteAddress):$($conn.RemotePort)"
                raw_event = @{
                    process_name = "$procName.exe"
                    pid = [int]$conn.OwningProcess
                    status = $conn.State.ToString()
                }
            }
        }

        if ($events.Count -gt 0) {
            $jsonPayload = $events | ConvertTo-Json -Depth 5 -Compress
            $body = @{ raw_data = $jsonPayload } | ConvertTo-Json -Compress

            $response = Invoke-RestMethod -Uri "$ServerUrl/api/ingest" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Sent $($events.Count) live connections -> Accepted" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Streaming to $ServerUrl... (Retrying)" -ForegroundColor Yellow
    }

    Start-Sleep -Seconds $IntervalSeconds
}
