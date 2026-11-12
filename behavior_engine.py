from collections import defaultdict
from datetime import datetime, timedelta


class BehavioralDetector:
    def __init__(self, port_threshold=15, window_seconds=60):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self.reported_scans = set()

    @staticmethod
    def parse_timestamp(value):
        if not value:
            return None

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return None

    def detect_port_scans(self, events):
        groups = defaultdict(list)

        for event in events:
            if event.get("event_type") != "flow":
                continue

            if event.get("proto", "").upper() != "TCP":
                continue

            src = event.get("src_ip")
            dst = event.get("dest_ip")
            port = event.get("dest_port")
            timestamp = self.parse_timestamp(
                event.get("timestamp")
            )

            if not all([src, dst, port, timestamp]):
                continue

            groups[(src, dst)].append(
                (timestamp, int(port))
            )

        detections = []

        for (src, dst), records in groups.items():
            records.sort(key=lambda x: x[0])

            for index, (start, _) in enumerate(records):
                end = start + timedelta(
                    seconds=self.window_seconds
                )

                window = [
                    (timestamp, port)
                    for timestamp, port in records[index:]
                    if timestamp <= end
                ]

                ports = {port for _, port in window}

                if len(ports) < self.port_threshold:
                    continue

                scan_key = (src, dst, tuple(sorted(ports)))

                if scan_key in self.reported_scans:
                    break

                self.reported_scans.add(scan_key)

                detections.append({
                    "detection_type": "BEHAVIOURAL_PORT_SCAN",
                    "severity": "HIGH",
                    "source_ip": src,
                    "destination_ip": dst,
                    "unique_destination_ports": len(ports),
                    "threshold": self.port_threshold,
                    "window_seconds": self.window_seconds,
                    "first_seen": start.isoformat(),
                    "description": (
                        f"{src} contacted {len(ports)} distinct "
                        f"TCP ports on {dst} within "
                        f"{self.window_seconds} seconds."
                    ),
                    "recommended_action": (
                        "Investigate the source host and correlate "
                        "with Suricata alerts."
                    )
                })

                break

        return detections


def analyse_network_behavior(events):
    detector = BehavioralDetector()
    return detector.detect_port_scans(events)
