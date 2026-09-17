import json
import unittest
from backend import database
from backend.models import IncidentStatus, SeverityLevel, ThreatCategory
from backend.normalizer import (
    normalize_suricata_event,
    normalize_zeek_json_event,
    parse_raw_text,
)
from backend.correlation import correlate_events
from backend.risk_engine import calculate_risk_and_confidence
from backend.timeline import build_attack_timeline
from backend.reporter import generate_incident_report
from backend.recommender import generate_recommendations
from backend.sample_data import get_scenario_c2_beaconing


class TestEDRPipeline(unittest.TestCase):

    def setUp(self):
        database.init_db()
        database.clear_all_data()

    def test_suricata_normalization(self):
        raw_suri = {
            "timestamp": "2026-09-18T02:32:14Z",
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "src_port": 49321,
            "dest_ip": "45.33.32.156",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "ET MALWARE Cobalt Strike Malleable C2 Periodic Beaconing",
                "severity": 1,
            },
        }
        event = normalize_suricata_event(raw_suri)
        self.assertEqual(event.source, "suricata")
        self.assertEqual(event.severity, 9)  # Mapped from 1 to 9
        self.assertEqual(event.src_ip, "192.168.1.50")
        self.assertEqual(event.dst_ip, "45.33.32.156")

    def test_zeek_normalization(self):
        raw_zeek = {
            "ts": 1789785000.0,
            "uid": "CZK-CONN-99",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49321,
            "id.resp_h": "45.33.32.156",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "conn_state": "SF",
        }
        event = normalize_zeek_json_event(raw_zeek)
        self.assertEqual(event.source, "zeek")
        self.assertEqual(event.src_ip, "192.168.1.50")
        self.assertEqual(event.dst_ip, "45.33.32.156")
        self.assertEqual(event.dst_port, 443)

    def test_correlation_and_incident_creation(self):
        # Ingest C2 scenario containing Suricata alert and Zeek telemetry
        raw_logs = get_scenario_c2_beaconing()
        events = parse_raw_text(raw_logs)
        self.assertEqual(len(events), 6)
        database.save_events_batch(events)

        # Run correlation
        incidents = correlate_events()
        self.assertEqual(len(incidents), 1)

        inc = incidents[0]
        self.assertEqual(inc.threat_category, ThreatCategory.COMMAND_AND_CONTROL)
        self.assertGreater(inc.risk_score, 60)
        self.assertGreater(inc.confidence, 70)
        self.assertIn("192.168.1.50", inc.affected_assets)

        # Verify evidence was saved
        evidence = database.get_incident_evidence(inc.id)
        self.assertGreater(len(evidence), 0)

        # Verify recommendations were generated
        recs = database.get_incident_recommendations(inc.id)
        self.assertGreater(len(recs), 0)

        # Verify attack timeline
        timeline = build_attack_timeline(events, inc.threat_category.value)
        has_inferred = any(t.is_inferred for t in timeline)
        self.assertTrue(has_inferred)

        # Verify report generation
        report_md = generate_incident_report(inc, timeline, evidence, recs)
        self.assertIn("SECURITY INCIDENT INVESTIGATION REPORT", report_md)
        self.assertIn(inc.id, report_md)

    def test_status_update(self):
        raw_logs = get_scenario_c2_beaconing()
        events = parse_raw_text(raw_logs)
        database.save_events_batch(events)
        incidents = correlate_events()
        inc_id = incidents[0].id

        self.assertEqual(incidents[0].status, IncidentStatus.NEW)
        database.update_incident_status(inc_id, IncidentStatus.INVESTIGATING.value)
        updated = database.get_incident_by_id(inc_id)
        self.assertEqual(updated.status, IncidentStatus.INVESTIGATING)


if __name__ == "__main__":
    unittest.main()
