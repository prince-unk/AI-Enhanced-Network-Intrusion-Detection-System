import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from storage import NIDSStorage


class StorageRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = NIDSStorage(str(Path(self.temp.name) / "test.db"))

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def old(days):
        return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    def test_alert_migration_and_retention(self):
        event = {"event_type": "alert", "timestamp": "old", "alert": {"signature": "old alert"}}
        with self.db.connect() as c:
            c.execute("INSERT INTO events(event_id,event_type,raw_json,created_at) VALUES(?,?,?,?)",
                      ("legacy-alert", "alert", json.dumps(event), self.old(31)))
        # Re-run schema init to exercise migration of legacy alert rows.
        self.db.init_db()
        with self.db.connect() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM alert_history WHERE alert_id='legacy-alert'").fetchone()[0], 1)
        deleted = self.db.apply_retention()
        self.assertEqual(deleted["alerts"], 1)
        self.assertEqual(deleted["alert_events"], 1)

    def test_routine_event_age_and_cap(self):
        with self.db.connect() as c:
            for i in range(4):
                c.execute("INSERT INTO events(event_id,event_type,raw_json,created_at) VALUES(?,?,?,?)",
                          (f"old-{i}", "dns", "{}", self.old(8)))
            for i in range(20005):
                c.execute("INSERT INTO events(event_id,event_type,raw_json,created_at) VALUES(?,?,?,?)",
                          (f"new-{i}", "dns", "{}", self.old(0)))
        result = self.db.apply_retention(routine_event_cap=20000)
        with self.db.connect() as c:
            remaining = c.execute("SELECT COUNT(*) FROM events WHERE event_type='dns'").fetchone()[0]
        self.assertEqual(result["routine_events_age"], 4)
        self.assertEqual(result["routine_events_cap"], 5)
        self.assertEqual(remaining, 20000)

    def test_behavior_incident_evidence_notes_audit_retention(self):
        with self.db.connect() as c:
            c.execute("INSERT INTO behavioral_detections(detection_id,detection_json,created_at) VALUES(?,?,?)",
                      ("old-behavior", "{}", self.old(31)))
            c.execute("""INSERT INTO incidents
                (incident_id,fingerprint,record_json,updated_at) VALUES(?,?,?,?)""",
                ("old-incident", "fp-old", "{}", self.old(61)))
            c.execute("INSERT INTO incident_evidence(incident_id,fingerprint,evidence_json) VALUES(?,?,?)",
                      ("old-incident", "ev-fp", "{}"))
            c.execute("INSERT INTO analyst_notes(incident_id,note,created_at) VALUES(?,?,?)",
                      ("old-incident", "old note", self.old(61)))
            c.execute("INSERT INTO audit_log(incident_id,action,created_at) VALUES(?,?,?)",
                      ("old-incident", "old action", self.old(61)))
        result = self.db.apply_retention()
        self.assertEqual(result["behavioral_detections"], 1)
        self.assertEqual(result["incidents"], 1)
        # Notes and evidence are removed by the incident's ON DELETE CASCADE.
        self.assertEqual(result["analyst_notes"], 0)
        self.assertEqual(result["audit_logs"], 1)
        with self.db.connect() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_evidence").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM analyst_notes").fetchone()[0], 0)

    def test_incident_update_audit_and_evidence_access(self):
        incident = {
            "incident_id": "INC-1", "fingerprint": "fp-1", "detection_type": "SURICATA_ALERT",
            "severity": "HIGH", "risk_score": 80, "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2", "signature": "Test alert", "first_seen": "now",
            "last_seen": "now", "event_count": 1, "description": "test",
            "recommended_action": "investigate", "status": "Open", "analyst_notes": "",
            "evidence": [{"kind": "test", "value": "evidence"}]
        }
        self.db.save_incident(incident)
        self.db.update_incident("INC-1", "Investigating", "Reviewed evidence")
        self.assertEqual(len(self.db.get_incidents()), 1)
        self.assertEqual(len(self.db.get_incident_evidence("INC-1")), 1)
        self.assertGreaterEqual(len(self.db.get_audit_log("INC-1")), 2)

    def test_ai_quota_reservation(self):
        allowed, reason, count = self.db.reserve_ai_request(daily_limit=2, per_minute_limit=2)
        self.assertTrue(allowed)
        self.assertEqual(reason, "allowed")
        self.assertEqual(count, 1)
        self.assertTrue(self.db.reserve_ai_request(daily_limit=2, per_minute_limit=2)[0])
        allowed, reason, count = self.db.reserve_ai_request(daily_limit=2, per_minute_limit=2)
        self.assertFalse(allowed)
        self.assertEqual(reason, "daily_limit")
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
