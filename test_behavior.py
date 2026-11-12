from behavior_engine import analyse_network_behavior
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc)

test_events = []

# Simulate one source contacting 20 different TCP ports.
for port in range(20, 40):
    test_events.append({
        "event_type": "flow",
        "timestamp": (
            now + timedelta(seconds=port - 20)
        ).isoformat(),
        "src_ip": "192.168.1.100",
        "dest_ip": "192.168.1.10",
        "dest_port": port,
        "proto": "TCP"
    })

results = analyse_network_behavior(test_events)

print("Behavioural detection results:")
for result in results:
    print(result)
