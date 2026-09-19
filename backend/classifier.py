from typing import List, Tuple
from backend.models import NormalizedEvent, ThreatCategory, ThreatDomain


def classify_incident_domain_and_threat(
    events: List[NormalizedEvent],
) -> Tuple[ThreatDomain, ThreatCategory, str, str, List[str], List[str]]:
    """
    Classifies a group of correlated events into:
    1. ThreatDomain (Authentication, Endpoint, Network, Application, Cross-Domain)
    2. ThreatCategory
    3. Incident Title
    4. Incident Description
    5. Indicators list
    6. MITRE ATT&CK Tags list
    """
    indicators: List[str] = []
    mitre_tags: List[str] = []

    # Aggregate events by domain
    auth_events = [e for e in events if e.domain == ThreatDomain.AUTHENTICATION or e.event_type in ("auth_failure", "auth_success")]
    endpoint_events = [e for e in events if e.domain == ThreatDomain.ENDPOINT or e.event_type in ("process_create", "fim_modification")]
    network_events = [e for e in events if e.domain == ThreatDomain.NETWORK or e.source in ("suricata", "zeek")]
    app_events = [e for e in events if e.domain == ThreatDomain.APPLICATION or e.event_type in ("app_auth_failure", "app_activity")]

    # Collect all MITRE tags
    for e in events:
        for t in e.mitre_tactics + e.mitre_techniques:
            if t and t not in mitre_tags:
                mitre_tags.append(t)

    # Check for specific indicators
    has_network_exploit = any(
        e.source == "suricata" and any(k in (e.signature or "").lower() for k in ["exploit", "cve", "injection", "overflow"])
        for e in network_events
    )
    if has_network_exploit:
        indicators.append("suricata_network_exploit")

    auth_failures = [e for e in auth_events if e.event_type == "auth_failure"]
    has_failed_logins = len(auth_failures) >= 2
    if has_failed_logins:
        indicators.append(f"multiple_failed_logins ({len(auth_failures)} attempts)")

    auth_successes = [e for e in auth_events if e.event_type == "auth_success"]
    has_successful_login = len(auth_successes) >= 1
    if has_successful_login:
        indicators.append("successful_login_after_failures" if has_failed_logins else "successful_login")

    has_fim_change = any(e.event_type == "fim_modification" or e.file_path for e in endpoint_events)
    if has_fim_change:
        indicators.append("unauthorized_file_modification_fim")

    has_suspicious_process = any(
        e.event_type == "process_create" or any(p in (e.process_name or "").lower() for p in ["powershell", "cmd", "certutil", "mshta", "payload"])
        for e in endpoint_events
    )
    if has_suspicious_process:
        indicators.append("suspicious_process_execution")

    affected_host = events[0].agent_name or events[0].dst_ip or "target-machine"
    source_actor = events[0].src_ip or "external attacker"

    # =========================================================================
    # 1. CROSS-DOMAIN CRITICAL ATTACK: ACCOUNT TAKEOVER / ENDPOINT COMPROMISE
    # (Network Exploit + Failed Logins + Successful Login + Endpoint Modification)
    # =========================================================================
    if (has_network_exploit or has_failed_logins) and has_successful_login and (has_suspicious_process or has_fim_change):
        if "T1078" not in mitre_tags:
            mitre_tags.extend(["T1078 (Valid Accounts)", "T1059 (Command and Scripting)", "T1110 (Brute Force)"])
        return (
            ThreatDomain.CROSS_DOMAIN,
            ThreatCategory.ACCOUNT_TAKEOVER,
            f"Possible Account Compromise and Endpoint Intrusion on {affected_host}",
            f"Correlated multi-sensor detection: Threat actor at {source_actor} attempted exploitation, performed credential attacks, achieved successful authentication, and executed suspicious endpoint modifications.",
            indicators,
            mitre_tags,
        )

    # =========================================================================
    # 2. AUTHENTICATION ATTACKS
    # =========================================================================
    if len(auth_failures) >= 4:
        # Check if password spraying across multiple usernames
        unique_users = {e.user for e in auth_failures if e.user}
        if len(unique_users) >= 3:
            indicators.append("password_spraying_multiple_accounts")
            if "T1110.003" not in mitre_tags:
                mitre_tags.append("T1110.003 (Password Spraying)")
            return (
                ThreatDomain.AUTHENTICATION,
                ThreatCategory.PASSWORD_SPRAYING,
                f"Password Spraying Attack Detected from {source_actor}",
                f"Authentication telemetry recorded {len(auth_failures)} failed login attempts distributed across {len(unique_users)} distinct user accounts ({', '.join(list(unique_users)[:3])}).",
                indicators,
                mitre_tags,
            )
        else:
            if "T1110" not in mitre_tags:
                mitre_tags.append("T1110 (Brute Force)")
            target_usr = list(unique_users)[0] if unique_users else "target account"
            return (
                ThreatDomain.AUTHENTICATION,
                ThreatCategory.BRUTE_FORCE,
                f"Credential Brute Force Attack targeting '{target_usr}'",
                f"High-frequency failed logon events ({len(auth_failures)} attempts) originating from {source_actor}.",
                indicators,
                mitre_tags,
            )

    # =========================================================================
    # 3. ENDPOINT ATTACKS
    # =========================================================================
    if has_fim_change and has_suspicious_process:
        if "T1547" not in mitre_tags:
            mitre_tags.extend(["T1547 (Persistence)", "T1059 (Scripting)"])
        return (
            ThreatDomain.ENDPOINT,
            ThreatCategory.ENDPOINT_COMPROMISE,
            f"Endpoint Tampering & Persistence Activity on {affected_host}",
            f"Host monitoring detected suspicious process execution coupled with unauthorized file modification in system directories.",
            indicators,
            mitre_tags,
        )

    if has_fim_change:
        if "T1565" not in mitre_tags:
            mitre_tags.append("T1565 (Data Manipulation - FIM)")
        return (
            ThreatDomain.ENDPOINT,
            ThreatCategory.FILE_INTEGRITY_VIOLATION,
            f"Critical File Integrity Violation on {affected_host}",
            "Wazuh FIM detected unauthorized modification or deletion of critical system binaries or configuration files.",
            indicators,
            mitre_tags,
        )

    if has_suspicious_process:
        if "T1059" not in mitre_tags:
            mitre_tags.append("T1059 (Command and Scripting Interpreter)")
        return (
            ThreatDomain.ENDPOINT,
            ThreatCategory.SUSPICIOUS_PROCESS,
            f"Suspicious Process Execution Detected on {affected_host}",
            "Wazuh Sysmon captured administrative or script host execution running unusual command lines or unapproved parameters.",
            indicators,
            mitre_tags,
        )

    # =========================================================================
    # 4. APPLICATION ABUSE
    # =========================================================================
    if app_events:
        auth_app_fails = [e for e in app_events if e.event_type == "app_auth_failure"]
        if len(auth_app_fails) >= 3:
            indicators.append("application_authorization_failures")
            if "T1078" not in mitre_tags:
                mitre_tags.append("T1078 (Valid Accounts / API Abuse)")
            return (
                ThreatDomain.APPLICATION,
                ThreatCategory.APPLICATION_ABUSE,
                f"API / Web Application Abuse targeting {affected_host}",
                f"Spike in HTTP 401/403 authorization failures detected from {source_actor} indicating possible parameter fuzzing or credential stuffing.",
                indicators,
                mitre_tags,
            )

    # =========================================================================
    # 5. NETWORK ATTACKS
    # =========================================================================
    sig_text = " ".join([(e.signature or "").lower() for e in network_events])
    if any(k in sig_text for k in ["c2", "beacon", "command and control", "trojan"]):
        if "T1071" not in mitre_tags:
            mitre_tags.append("T1071 (Application Layer Protocol - C2)")
        return (
            ThreatDomain.NETWORK,
            ThreatCategory.COMMAND_AND_CONTROL,
            f"Command and Control (C2) Communication by {affected_host}",
            f"Network IDS matched periodic beaconing and suspicious TLS sessions communicating with {source_actor}.",
            indicators,
            mitre_tags,
        )

    if any(k in sig_text for k in ["scan", "nmap", "port scan"]):
        if "T1046" not in mitre_tags:
            mitre_tags.append("T1046 (Network Service Discovery)")
        return (
            ThreatDomain.NETWORK,
            ThreatCategory.SCANNING,
            f"Network Port Reconnaissance / Scanning by {source_actor}",
            f"Suricata and live sensors detected systematic port scanning targeting {affected_host}.",
            indicators,
            mitre_tags,
        )

    # Default fallback
    domain = events[0].domain if events else ThreatDomain.CROSS_DOMAIN
    return (
        domain,
        ThreatCategory.UNKNOWN,
        f"Suspicious Security Event on {affected_host}",
        f"Correlated security telemetry from {source_actor} requires analyst investigation.",
        indicators,
        mitre_tags,
    )
