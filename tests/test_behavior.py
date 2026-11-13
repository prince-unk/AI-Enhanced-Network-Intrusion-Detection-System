"""Automated behavioural detection regression tests (offline)."""
import unittest
from datetime import datetime, timedelta, timezone

from behavior_engine import analyse_network_behavior


class BehaviorDetectionTests(unittest.TestCase):
    def test_detects_multi_port_scan_pattern(self):
        now = datetime.now(timezone.utc)
        events = [
            {
                "event_type": "flow",
                "timestamp": (now + timedelta(seconds=i)).isoformat(),
                "src_ip": "192.168.1.100",
                "dest_ip": "192.168.1.10",
                "dest_port": 20 + i,
                "proto": "TCP",
            }
            for i in range(20)
        ]
        results = analyse_network_behavior(events)
        self.assertTrue(results)
        self.assertTrue(any("192.168.1.100" in str(item) for item in results))

    def test_empty_input_returns_no_detection(self):
        self.assertEqual(analyse_network_behavior([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
