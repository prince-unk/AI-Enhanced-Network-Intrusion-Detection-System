"""Offline unit tests for Gemini response validation; never calls the live API."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from nids_core import _normalise_llm_result, local_triage, enrich_alert, llm_triage


class GeminiTriageTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "timestamp": "2026-11-13T10:00:00+00:00",
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "src_port": 51000,
            "dest_ip": "198.51.100.20",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Potential SSH Scan",
                "category": "Attempted Information Leak",
                "severity": 2,
                "signature_id": 2001219,
            },
        }

    def test_local_fallback_has_full_analyst_schema(self):
        result = local_triage(self.event)
        expected = {
            "provider", "severity", "summary", "recommended_action", "reason",
            "threat_context", "potential_impact", "investigation_steps",
            "response_recommendations", "false_positive_considerations",
            "mitre_attack", "confidence", "confidence_reason", "evidence_used",
            "limitations",
        }
        self.assertTrue(expected.issubset(result))
        self.assertGreaterEqual(len(result["investigation_steps"]), 2)
        self.assertTrue(result["false_positive_considerations"])

    def test_normalise_structured_gemini_response(self):
        raw = {
            "summary": "Possible SSH reconnaissance.",
            "severity": "medium",
            "recommended_action": "Review source activity.",
            "reason": "Multiple ports were observed.",
            "threat_context": "Could indicate service discovery.",
            "potential_impact": "May expose services to follow-on attempts.",
            "investigation_steps": ["Review flow records", "Check authorised scanner list"],
            "response_recommendations": ["Monitor the source"],
            "false_positive_considerations": ["Could be an authorised scan"],
            "mitre_attack": [{
                "technique_id": "T1046", "technique": "Network Service Discovery",
                "tactic": "Discovery", "rationale": "Port enumeration pattern"
            }, {"technique_id": "NOT-REAL", "technique": "Invented", "tactic": "x"}],
            "confidence": "medium",
            "confidence_reason": "Only alert metadata was available.",
            "evidence_used": ["Suricata signature"],
            "limitations": ["No packet payload was available"],
        }
        result = _normalise_llm_result(raw, "gemini-api")
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(len(result["mitre_attack"]), 1)
        self.assertEqual(result["mitre_attack"][0]["technique_id"], "T1046")
        self.assertEqual(result["confidence"], "MEDIUM")


    def test_llm_triage_parses_mocked_gemini_response(self):
        import os
        payload = {
            "summary": "Possible SSH service reconnaissance.",
            "severity": "MEDIUM",
            "recommended_action": "Validate whether the source is authorised.",
            "reason": "The Suricata signature identifies scanning activity.",
            "threat_context": "Could indicate service discovery.",
            "potential_impact": "May precede attempts against exposed services.",
            "investigation_steps": ["Review source history", "Check approved scanners"],
            "response_recommendations": ["Monitor and investigate"],
            "false_positive_considerations": ["Could be authorised testing"],
            "mitre_attack": [],
            "confidence": "LOW",
            "confidence_reason": "Only one alert record was supplied.",
            "evidence_used": ["Signature and endpoint metadata"],
            "limitations": ["No packet payload was supplied"],
        }
        fake_client = SimpleNamespace(models=SimpleNamespace(
            generate_content=lambda **kwargs: SimpleNamespace(text=__import__("json").dumps(payload))
        ))
        fake_genai = SimpleNamespace(Client=lambda **kwargs: fake_client)
        fake_google = SimpleNamespace(genai=fake_genai)
        with patch.dict("sys.modules", {"google": fake_google}), patch.dict(os.environ, {"GEMINI_API_KEY": "unit-test-key", "GEMINI_MODEL": "test-model"}):
            result = llm_triage(self.event)
        self.assertEqual(result["provider"], "gemini-api")
        self.assertEqual(result["summary"], payload["summary"])
        self.assertEqual(result["investigation_steps"], payload["investigation_steps"])

    def test_invalid_response_is_rejected(self):
        self.assertIsNone(_normalise_llm_result({"summary": "missing fields"}, "gemini-api"))
        self.assertIsNone(_normalise_llm_result([], "gemini-api"))

    def test_enrichment_uses_local_fallback_without_api_key(self):
        import os
        previous = os.environ.pop("GEMINI_API_KEY", None)
        try:
            enriched = enrich_alert(self.event, cache={})
        finally:
            if previous is not None:
                os.environ["GEMINI_API_KEY"] = previous
        self.assertEqual(enriched["triage"]["provider"], "local-rule-based-fallback")
        self.assertIn("investigation_steps", enriched["triage"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
