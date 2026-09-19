import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from backend import database
from backend.models import NormalizedEvent
from backend.normalizer import parse_raw_text, normalize_wazuh_event, normalize_suricata_event


class CyberguardDetectionAdapter:
    """
    CYBERGUARD Detection Module Adapter.
    Gateway receiving security alerts from Wazuh Server (backbone)
    and Suricata Network IDS/IPS sensor.
    """

    def process_wazuh_alert(self, alert_data: Union[Dict[str, Any], str]) -> List[NormalizedEvent]:
        """Processes a single or batch of Wazuh 4.x security alerts."""
        if isinstance(alert_data, str):
            events = parse_raw_text(alert_data, default_source="wazuh")
        elif isinstance(alert_data, dict):
            events = [normalize_wazuh_event(alert_data)]
        elif isinstance(alert_data, list):
            events = [normalize_wazuh_event(item) for item in alert_data if isinstance(item, dict)]
        else:
            events = []

        if events:
            database.save_events_batch(events)
        return events

    def process_suricata_eve(self, eve_data: Union[Dict[str, Any], str]) -> List[NormalizedEvent]:
        """Processes raw Suricata EVE JSON alerts."""
        if isinstance(eve_data, str):
            events = parse_raw_text(eve_data, default_source="suricata")
        elif isinstance(eve_data, dict):
            events = [normalize_suricata_event(eve_data)]
        elif isinstance(eve_data, list):
            events = [normalize_suricata_event(item) for item in eve_data if isinstance(item, dict)]
        else:
            events = []

        if events:
            database.save_events_batch(events)
        return events

    def process_generic_stream(self, raw_text: str) -> List[NormalizedEvent]:
        """Auto-detects and processes mixed telemetry streams."""
        events = parse_raw_text(raw_text)
        if events:
            database.save_events_batch(events)
        return events


# Global adapter instance
detection_adapter = CyberguardDetectionAdapter()
