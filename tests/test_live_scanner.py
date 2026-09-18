import unittest
from backend import database
from backend.live_scanner import LiveNetworkScanner, is_external_ip
from backend.correlation import correlate_events


class TestLiveScanner(unittest.TestCase):

    def setUp(self):
        database.init_db()
        database.clear_all_data()

    def test_external_ip_helper(self):
        self.assertFalse(is_external_ip("127.0.0.1"))
        self.assertFalse(is_external_ip("192.168.1.100"))
        self.assertFalse(is_external_ip("10.0.0.1"))
        self.assertTrue(is_external_ip("8.8.8.8"))
        self.assertTrue(is_external_ip("142.250.190.46"))

    def test_live_system_scan_once(self):
        scanner = LiveNetworkScanner(poll_interval_seconds=1.0)
        events = scanner.scan_once()
        # On any running computer with network access, psutil finds active connections
        self.assertIsInstance(events, list)
        # Verify events were persisted to database
        db_events = database.get_all_events(limit=100)
        self.assertEqual(len(events), len(db_events))

    def test_live_scanner_status(self):
        scanner = LiveNetworkScanner(poll_interval_seconds=1.0)
        status = scanner.get_status()
        self.assertFalse(status["is_scanning"])
        self.assertIn("scanned_connections", status)
        self.assertIn("alerts_generated", status)


if __name__ == "__main__":
    unittest.main()
