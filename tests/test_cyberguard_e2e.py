import unittest
from backend import database
from backend.adapter import detection_adapter
from backend.correlation import correlate_events
from backend.models import IncidentStatus, SeverityLevel, ThreatCategory, ThreatDomain
from backend.sample_data import (
    get_scenario_account_compromise,
    get_scenario_password_spray,
    get_scenario_endpoint_persistence,
    get_scenario_app_abuse,
)
from backend.wazuh_ips import ips_engine


class TestCyberguardDetectionModule(unittest.TestCase):

    def setUp(self):
        database.init_db()
        database.clear_all_data()

    def test_user_exact_account_compromise_scenario(self):
        """
        Tests the user's exact scenario:
        Suricata Network Exploit + Wazuh 5 failed logins + Successful login +
        New executable + Critical file modified -> Possible Account Compromise (Risk: CRITICAL).
        """
        raw_attack_data = get_scenario_account_compromise()
        events = detection_adapter.process_generic_stream(raw_attack_data)
        self.assertEqual(len(events), 9)  # 1 Suricata + 5 failed auth + 1 success auth + 1 file created + 1 FIM modified

        incidents = correlate_events()
        self.assertGreaterEqual(len(incidents), 1)

        inc = incidents[0]
        # Verify Classification
        self.assertEqual(inc.domain, ThreatDomain.CROSS_DOMAIN)
        self.assertEqual(inc.threat_category, ThreatCategory.ACCOUNT_TAKEOVER)

        # Verify Decoupled Risk & Confidence
        self.assertEqual(inc.severity, SeverityLevel.CRITICAL)
        self.assertGreaterEqual(inc.risk_score, 85)
        self.assertGreaterEqual(inc.confidence, 85)

        # Verify Evidence Store
        evidence = database.get_incident_evidence(inc.id)
        evidence_types = {e.type for e in evidence}
        self.assertIn("IDS Exploit Alert", evidence_types)
        self.assertIn("Authentication Failure", evidence_types)
        self.assertIn("Successful Login", evidence_types)
        self.assertIn("File Integrity Modification (FIM)", evidence_types)

        # Verify Recommendations
        recs = database.get_incident_recommendations(inc.id)
        rec_texts = " ".join([r.recommendation.lower() for r in recs])
        self.assertIn("reset credentials", rec_texts)
        self.assertIn("isolate endpoint", rec_texts)
        self.assertIn("block", rec_texts)

        # Verify Real-time Notification was emitted
        notifs = database.get_recent_notifications()
        self.assertGreaterEqual(len(notifs), 1)
        self.assertEqual(notifs[0].level, "CRITICAL")
        self.assertIn(inc.id, notifs[0].incident_id)

    def test_active_response_ips_containment(self):
        """Tests that active response firewall blocking and process kill mark incident as contained."""
        raw_attack_data = get_scenario_account_compromise()
        detection_adapter.process_generic_stream(raw_attack_data)
        incidents = correlate_events()
        inc = incidents[0]
        self.assertFalse(inc.is_contained)

        # Trigger Active Response block
        res = ips_engine.block_ip("185.220.101.5", reason="Unit Test Active Response")
        self.assertTrue(res["success"])
        database.update_incident_status(inc.id, IncidentStatus.CONTAINED.value)

        updated_inc = database.get_incident_by_id(inc.id)
        self.assertEqual(updated_inc.status, IncidentStatus.CONTAINED)
        self.assertTrue(updated_inc.is_contained)

        # Clean up block
        ips_engine.unblock_ip("185.220.101.5")

    def test_auth_domain_password_spray(self):
        """Tests Authentication Domain: Password Spraying."""
        raw = get_scenario_password_spray()
        detection_adapter.process_generic_stream(raw)
        incidents = correlate_events()
        self.assertGreaterEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.domain, ThreatDomain.AUTHENTICATION)
        self.assertEqual(inc.threat_category, ThreatCategory.PASSWORD_SPRAYING)

    def test_endpoint_domain_persistence(self):
        """Tests Endpoint Domain: PowerShell + FIM."""
        raw = get_scenario_endpoint_persistence()
        detection_adapter.process_generic_stream(raw)
        incidents = correlate_events()
        self.assertGreaterEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.domain, ThreatDomain.ENDPOINT)

    def test_application_domain_abuse(self):
        """Tests Application Domain: 401/403 abuse."""
        raw = get_scenario_app_abuse()
        detection_adapter.process_generic_stream(raw)
        incidents = correlate_events()
        self.assertGreaterEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.domain, ThreatDomain.APPLICATION)


if __name__ == "__main__":
    unittest.main()
