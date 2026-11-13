"""Offline tests for incident correlation and incident-level AI triage."""
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from incident_engine import IncidentCorrelator
from nids_core import (
    _normalise_llm_result,
    enrich_incident,
    local_incident_triage,
    llm_incident_triage,
)


class IncidentCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.correlator = IncidentCorrelator(correlation_window=300)

    def test_related_alerts_from_same_source_are_grouped(self):
        events = [
            {"event_type": "alert", "timestamp": "2026-11-13T10:00:00+00:00",
             "src_ip": "192.0.2.10", "dest_ip": "198.51.100.10",
             "alert": {"signature": "Scan A", "severity": 2}},
            {"event_type": "alert", "timestamp": "2026-11-13T10:02:00+00:00",
             "src_ip": "192.0.2.10", "dest_ip": "198.51.100.20",
             "alert": {"signature": "Scan B", "severity": 1}},
        ]
        incidents = self.correlator.ingest(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 2)
        self.assertEqual(len(incidents[0]["destinations"]), 2)
        self.assertGreaterEqual(incidents[0]["risk_score"], 35)

    def test_duplicate_event_is_not_counted_twice(self):
        event = {"event_type": "alert", "timestamp": "2026-11-13T10:00:00+00:00",
                 "src_ip": "192.0.2.10", "dest_ip": "198.51.100.10",
                 "alert": {"signature": "Scan A", "severity": 2}}
        self.correlator.ingest([event])
        incidents = self.correlator.ingest([event])
        self.assertEqual(incidents[0]["event_count"], 1)

    def test_risk_score_explains_severity_corroboration_and_diversity(self):
        events = [
            {"event_type": "alert", "timestamp": "2026-11-13T10:00:00+00:00",
             "src_ip": "192.0.2.10", "dest_ip": "198.51.100.10",
             "alert": {"signature": "Critical alert", "severity": 1}},
            {"event_type": "alert", "timestamp": "2026-11-13T10:01:00+00:00",
             "src_ip": "192.0.2.10", "dest_ip": "198.51.100.20",
             "alert": {"signature": "Supporting alert", "severity": 2}},
        ]
        incident = self.correlator.ingest(events)[0]
        self.assertEqual(incident["risk_score"], 45)
        self.assertEqual(incident["risk_scoring_method"], "evidence_weighted_v1")
        factors = {item["name"]: item for item in incident["risk_factors"]}
        self.assertEqual(factors["Detection severity"]["points"], 35)
        self.assertEqual(factors["Corroborating events"]["points"], 5)
        self.assertEqual(factors["Destination diversity"]["points"], 5)
        self.assertEqual(factors["Behavioural evidence"]["points"], 0)
        self.assertTrue(incident["risk_score_limitations"])

    def test_behavioral_evidence_contributes_to_explainable_score(self):
        behavioral = [{
            "source_ip": "192.0.2.11", "destination_ip": "198.51.100.11",
            "description": "Multiple destination ports",
            "detection_type": "PORT_SCAN", "severity": "HIGH",
            "first_seen": "2026-11-13T10:00:00+00:00"
        }]
        incident = self.correlator.ingest([], behavioral)[0]
        factors = {item["name"]: item for item in incident["risk_factors"]}
        self.assertEqual(factors["Behavioural evidence"]["points"], 10)
        self.assertEqual(incident["risk_score"], 50)

    def test_risk_score_is_capped_at_100(self):
        events = []
        for index in range(12):
            events.append({
                "event_type": "alert",
                "timestamp": f"2026-11-13T10:{index:02d}:00+00:00",
                "src_ip": "192.0.2.12",
                "dest_ip": f"198.51.100.{index + 1}",
                "alert": {"signature": f"Alert {index}", "severity": 1}
            })
        incident = self.correlator.ingest(events)[0]
        self.assertEqual(incident["risk_score"], 75)
        self.assertLessEqual(incident["risk_score"], 100)

    def test_events_outside_window_create_separate_incidents(self):
        events = [
            {"event_type": "alert", "timestamp": "2026-11-13T10:00:00+00:00",
             "src_ip": "192.0.2.10", "dest_ip": "198.51.100.10",
             "alert": {"signature": "Scan A", "severity": 2}},
            {"event_type": "alert", "timestamp": "2026-11-13T10:10:00+00:00",
             "src_ip": "192.0.2.10", "dest_ip": "198.51.100.10",
             "alert": {"signature": "Scan B", "severity": 2}},
        ]
        self.assertEqual(len(self.correlator.ingest(events)), 2)


class IncidentAITests(unittest.TestCase):
    def setUp(self):
        self.incident = {
            "incident_id": "INC-TEST-001", "detection_type": "CORRELATED_ACTIVITY",
            "severity": "HIGH", "risk_score": 85, "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.10, 198.51.100.20",
            "signature": "Correlated scan activity", "first_seen": "2026-11-13T10:00:00+00:00",
            "last_seen": "2026-11-13T10:02:00+00:00", "event_count": 2,
            "description": "Two related detections.",
            "evidence": [{"signature": "Scan A"}, {"signature": "Scan B"}],
            "analyst_notes": ""
        }

    def test_local_incident_analysis_has_full_schema(self):
        result = local_incident_triage(self.incident)
        for key in ("summary", "reason", "threat_context", "potential_impact",
                    "investigation_steps", "response_recommendations",
                    "false_positive_considerations", "confidence", "limitations"):
            self.assertIn(key, result)
        self.assertEqual(result["provider"], "local-rule-based-fallback")
        self.assertGreaterEqual(len(result["investigation_steps"]), 3)

    def test_mocked_gemini_incident_response(self):
        payload = {
            "summary": "Correlated reconnaissance may be occurring.", "severity": "HIGH",
            "recommended_action": "Validate source ownership and investigate.",
            "reason": "Two related detections share a source and time window.",
            "threat_context": "Possible network service discovery.",
            "potential_impact": "Exposed services may be targeted later.",
            "investigation_steps": ["Review EVE timeline", "Check authorised scanners"],
            "response_recommendations": ["Preserve evidence"],
            "false_positive_considerations": ["Could be authorised scanning"],
            "mitre_attack": [], "confidence": "MEDIUM",
            "confidence_reason": "Only network alert metadata was supplied.",
            "evidence_used": ["Scan A", "Scan B"], "limitations": ["No endpoint telemetry"]
        }
        fake_client = SimpleNamespace(models=SimpleNamespace(
            generate_content=lambda **kwargs: SimpleNamespace(text=json.dumps(payload))
        ))
        fake_google = SimpleNamespace(genai=SimpleNamespace(Client=lambda **kwargs: fake_client))
        with patch.dict("sys.modules", {"google": fake_google}), patch.dict(
            os.environ, {"GEMINI_API_KEY": "unit-test-key", "GEMINI_MODEL": "test-model"}
        ):
            result = llm_incident_triage(self.incident)
        self.assertEqual(result["provider"], "gemini-api")
        self.assertIn("Correlated reconnaissance", result["summary"])

    def test_invalid_incident_ai_response_rejected(self):
        self.assertIsNone(_normalise_llm_result({"summary": "incomplete"}, "gemini-api"))

    def test_incident_fallback_when_api_unavailable(self):
        with patch.dict(os.environ, {}, clear=True):
            result = enrich_incident(self.incident, cache={})
        self.assertEqual(result["provider"], "local-rule-based-fallback")


if __name__ == "__main__":
    unittest.main(verbosity=2)
