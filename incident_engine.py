import hashlib
import json
from datetime import datetime, timedelta, timezone


class IncidentCorrelator:
    def __init__(self, correlation_window=300):
        self.correlation_window = correlation_window
        self.incidents = {}
        self.event_fingerprints = set()

    @staticmethod
    def parse_time(value):
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

        if not value:
            return datetime.now(timezone.utc)

        try:
            parsed = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )
            return parsed if parsed.tzinfo else parsed.replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def fingerprint(event):
        encoded = json.dumps(
            event, sort_keys=True, default=str
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def risk_level(score):
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def event_weight(event):
        event_type = event.get("event_type", "")

        if event_type == "behavioral":
            return 40 if event.get("severity") == "HIGH" else 25

        alert = event.get("alert") or {}
        try:
            severity = int(alert.get("severity", 3))
        except (ValueError, TypeError):
            severity = 3

        return {1: 35, 2: 25, 3: 10}.get(severity, 10)

    def normalize_event(self, event, event_type):
        if event_type == "behavioral":
            source = event.get("source_ip")
            destination = event.get("destination_ip")
            description = event.get("description", "Behavioural detection")
            signature = event.get("detection_type", "Behavioural detection")
            timestamp = event.get("first_seen")
        else:
            alert = event.get("alert") or {}
            source = event.get("src_ip")
            destination = event.get("dest_ip")
            description = alert.get("category", "Suricata alert")
            signature = alert.get("signature", "Unknown signature")
            timestamp = event.get("timestamp")

        return {
            "event_type": event_type,
            "timestamp": self.parse_time(timestamp),
            "source_ip": source or "unknown",
            "destination_ip": destination or "unknown",
            "signature": signature,
            "description": description,
            "weight": self.event_weight({
                **event,
                "event_type": event_type
            }),
            "evidence": event
        }

    def ingest(self, events, behavioral_detections=None):
        normalized = []

        for event in events:
            if event.get("event_type") == "alert" or event.get("alert"):
                normalized.append(
                    self.normalize_event(event, "suricata")
                )

        for event in behavioral_detections or []:
            normalized.append(
                self.normalize_event(event, "behavioral")
            )

        for event in normalized:
            fingerprint = self.fingerprint(event["evidence"])

            if fingerprint in self.event_fingerprints:
                continue

            self.event_fingerprints.add(fingerprint)
            self._add_event(event)

        return self.get_incidents()

    def _add_event(self, event):
        source = event["source_ip"]
        destination = event["destination_ip"]
        timestamp = event["timestamp"]

        # Correlate by source IP within the configured time window.
        incident = None

        for candidate in self.incidents.values():
            if candidate["source_ip"] != source:
                continue

            last_seen = candidate["_last_seen"]
            age = abs((timestamp - last_seen).total_seconds())

            if age <= self.correlation_window:
                incident = candidate
                break

        if incident is None:
            incident_id = "INC-" + datetime.now().strftime(
                "%Y%m%d"
            ) + "-" + hashlib.sha1(
                f"{source}-{timestamp.isoformat()}".encode()
            ).hexdigest()[:8].upper()

            incident = {
                "incident_id": incident_id,
                "source_ip": source,
                "destinations": [],
                "first_seen": timestamp.isoformat(),
                "last_seen": timestamp.isoformat(),
                "event_count": 0,
                "risk_score": 0,
                "risk_level": "LOW",
                "status": "OPEN",
                "evidence": [],
                "_last_seen": timestamp
            }

            self.incidents[incident_id] = incident

        incident["_last_seen"] = max(
            incident["_last_seen"], timestamp
        )
        incident["last_seen"] = incident["_last_seen"].isoformat()

        if destination not in incident["destinations"]:
            incident["destinations"].append(destination)

        incident["event_count"] += 1
        incident["evidence"].append({
            "event_type": event["event_type"],
            "timestamp": timestamp.isoformat(),
            "destination_ip": destination,
            "signature": event["signature"],
            "description": event["description"],
            "weight": event["weight"]
        })

        # Explainable score: strongest evidence + supporting events.
        weights = [
            item["weight"] for item in incident["evidence"]
        ]

        score = max(weights) + min(
            40, max(0, len(weights) - 1) * 10
        )

        incident["risk_score"] = min(100, score)
        incident["risk_level"] = self.risk_level(score)

        incident["recommended_action"] = self.recommend_action(
            incident["risk_level"]
        )

    @staticmethod
    def recommend_action(level):
        actions = {
            "CRITICAL": (
                "Immediately investigate the source host, preserve "
                "evidence and follow the approved containment procedure."
            ),
            "HIGH": (
                "Investigate the source host, validate the activity "
                "and correlate endpoint and network logs."
            ),
            "MEDIUM": (
                "Review related events, verify whether the activity "
                "is authorised and monitor the source."
            ),
            "LOW": (
                "Continue monitoring and review if additional evidence "
                "appears."
            )
        }
        return actions[level]

    def update_status(self, incident_id, status):
        allowed = {"OPEN", "INVESTIGATING", "RESOLVED"}

        if status not in allowed:
            raise ValueError(f"Invalid status: {status}")

        if incident_id not in self.incidents:
            raise KeyError(f"Incident not found: {incident_id}")

        self.incidents[incident_id]["status"] = status

    def get_incidents(self):
        return [
            {
                key: value
                for key, value in incident.items()
                if not key.startswith("_")
            }
            for incident in sorted(
                self.incidents.values(),
                key=lambda item: item["_last_seen"],
                reverse=True
            )
        ]
