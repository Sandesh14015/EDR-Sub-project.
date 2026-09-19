import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional
from backend import database


class WazuhActiveResponseIPS:
    """
    Wazuh 4.x style Active Response & Intrusion Prevention System (IPS).
    Executes automated or one-click containment actions:
    1. Blocking offending remote IP in firewall (netsh on Windows / iptables on Linux)
    2. Terminating malicious process by PID (taskkill on Windows / kill -9 on Linux)
    """

    def __init__(self):
        self._blocked_ips: Dict[str, Dict[str, str]] = {}

    def block_ip(self, ip_address: str, reason: str = "Automated Intrusion Prevention") -> Dict[str, Any]:
        """Blocks all inbound and outbound traffic to/from a remote IP."""
        if not ip_address or ip_address in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            return {"success": False, "message": "Cannot block loopback or invalid address."}

        rule_name = f"CYBERGUARD_BLOCK_{ip_address.replace(':', '_')}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Execute system firewall block
        is_windows = sys.platform.startswith("win")
        success = True
        cmd_output = ""

        if is_windows:
            # Block inbound
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_address}'
            # Block outbound
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_address}'
            try:
                subprocess.run(cmd_in, shell=True, capture_output=True, text=True, check=False)
                res = subprocess.run(cmd_out, shell=True, capture_output=True, text=True, check=False)
                cmd_output = res.stdout or res.stderr
            except Exception as e:
                success = False
                cmd_output = str(e)
        else:
            # Linux iptables fallback
            try:
                subprocess.run(f"iptables -A INPUT -s {ip_address} -j DROP", shell=True, check=False)
                subprocess.run(f"iptables -A OUTPUT -d {ip_address} -j DROP", shell=True, check=False)
            except Exception as e:
                success = False
                cmd_output = str(e)

        self._blocked_ips[ip_address] = {
            "ip": ip_address,
            "blocked_at": now_iso,
            "reason": reason,
            "rule_name": rule_name,
        }

        return {
            "success": success,
            "ip": ip_address,
            "message": f"IP {ip_address} has been blocked at the host firewall.",
            "details": cmd_output,
            "blocked_at": now_iso,
        }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Removes firewall block rule for the specified IP."""
        rule_name = f"CYBERGUARD_BLOCK_{ip_address.replace(':', '_')}"
        is_windows = sys.platform.startswith("win")
        if is_windows:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
            subprocess.run(cmd, shell=True, capture_output=True, check=False)
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
            subprocess.run(cmd, shell=True, capture_output=True, check=False)
        else:
            subprocess.run(f"iptables -D INPUT -s {ip_address} -j DROP", shell=True, check=False)
            subprocess.run(f"iptables -D OUTPUT -d {ip_address} -j DROP", shell=True, check=False)

        if ip_address in self._blocked_ips:
            del self._blocked_ips[ip_address]

        return {"success": True, "message": f"IP {ip_address} unblocked."}

    def terminate_process(self, pid: int, process_name: Optional[str] = None) -> Dict[str, Any]:
        """Terminates a suspicious process by PID."""
        if not pid or pid <= 4:
            return {"success": False, "message": "Cannot terminate system PID."}

        is_windows = sys.platform.startswith("win")
        try:
            if is_windows:
                cmd = f"taskkill /F /PID {pid}"
            else:
                cmd = f"kill -9 {pid}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            return {
                "success": res.returncode == 0,
                "pid": pid,
                "message": f"Process {process_name or ''} (PID: {pid}) terminated: {res.stdout.strip() or res.stderr.strip()}",
            }
        except Exception as e:
            return {"success": False, "pid": pid, "message": f"Failed to terminate process: {e}"}

    def get_blocked_ips(self) -> List[Dict[str, str]]:
        return list(self._blocked_ips.values())


ips_engine = WazuhActiveResponseIPS()
