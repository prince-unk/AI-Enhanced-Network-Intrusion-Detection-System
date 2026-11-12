from dotenv import load_dotenv
load_dotenv()
import json
import hashlib
import os
from datetime import datetime

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from nids_core import load_events, enrich_alert

from behavior_engine import BehavioralDetector
from storage import NIDSStorage

# Shared local database for dashboard persistence.
nids_db = NIDSStorage()

if not st.session_state.get("nids_retention_applied", False):
    try:
        nids_db.apply_retention(routine_event_cap=20000)
        st.session_state["nids_retention_applied"] = True
    except Exception as exc:
        st.warning(f"Database retention cleanup could not run: {exc}")

def read_new_eve_events(path, buffer_limit=500, alert_limit=200):
    """Read only newly appended Suricata EVE records."""

    state = st.session_state

    try:
        stat = os.stat(path)
    except OSError as exc:
        st.error(f"Cannot access EVE file: {exc}")
        return [], []

    inode = getattr(stat, "st_ino", None)

    # First startup: skip historical records and start at EOF.
    if "eve_offset" not in state:
        state.eve_offset = stat.st_size
        state.eve_inode = inode
        state.eve_pending = ""
        # Restore recent saved records, but keep the EVE cursor at EOF so
        # historical log entries are not replayed as new traffic.
        restored_events = nids_db.get_events(limit=buffer_limit)
        state.live_events = restored_events
        state.live_alerts = [
            event for event in restored_events
            if event.get("event_type") == "alert" or event.get("alert")
        ][-alert_limit:]
        state.event_totals = {}
        for restored in restored_events:
            event_type = str(restored.get("event_type", "unknown")).lower()
            state.event_totals[event_type] = state.event_totals.get(event_type, 0) + 1
        state.session_alert_total = len(state.live_alerts)
        state.last_event_timestamp = (
            restored_events[-1].get("timestamp") if restored_events else None
        )
        state.last_event_received = None

    # Detect file rotation or truncation.
    if (
        state.eve_inode != inode
        or stat.st_size < state.eve_offset
    ):
        state.eve_offset = 0
        state.eve_inode = inode
        state.eve_pending = ""

    new_events = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            file.seek(state.eve_offset)
            chunk = file.read()
            state.eve_offset = file.tell()

        data = state.eve_pending + chunk
        lines = data.split("\n")

        # Retain an incomplete final line for the next refresh.
        state.eve_pending = lines.pop()

        for line in lines:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    new_events.append(event)
            except json.JSONDecodeError:
                continue

    except OSError as exc:
        st.error(f"Error reading EVE file: {exc}")
        return state.live_events, state.live_alerts


# Persist only newly appended EVE records; save_events deduplicates them.
    if new_events:
        try:
            nids_db.save_events(new_events)
        except Exception as exc:
            st.warning(f"SQLite event persistence unavailable: {exc}")

    # Update cumulative session statistics.
    for event in new_events:
        event_type = str(
            event.get("event_type", "unknown")
        ).lower()

        state.event_totals[event_type] = (
            state.event_totals.get(event_type, 0) + 1
        )

        timestamp = event.get("timestamp")
        if timestamp:
            state.last_event_timestamp = timestamp

    if new_events:
        state.last_event_received = datetime.now().astimezone()

    state.session_alert_total += len([
        event for event in new_events
        if event.get("event_type") == "alert" or event.get("alert")
    ])

    # Display history is loaded from SQLite on every rerun. This is important:
    # changing the slider from 500 to (for example) 1700 must fetch older saved
    # rows, not merely enlarge the in-memory buffer that currently holds 500.
    # Ingestion remains incremental above; this query does not reread the EVE file
    # and does not create duplicate database records.
    try:
        state.live_events = nids_db.get_events(limit=buffer_limit)
    except Exception as exc:
        # Keep the dashboard usable if SQLite is temporarily unavailable.
        state.live_events.extend(new_events)
        state.live_events = state.live_events[-buffer_limit:]
        st.warning(f"Could not reload event history from SQLite: {exc}")

    # Maintain a separate alert history.
    new_alerts = [
        event for event in new_events
        if event.get("event_type") == "alert" or event.get("alert")
    ]

    state.live_alerts.extend(new_alerts)
    state.live_alerts = state.live_alerts[-alert_limit:]

    return state.live_events, state.live_alerts

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AI-Enhanced NIDS",
    page_icon=":shield:",
    layout="wide"
)

st.title(":shield: AI-Enhanced Network Intrusion Detection System")
st.caption(
    "Suricata signature detection • Live network monitoring "
    "• Explainable alert triage"
)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.header("Monitoring configuration")

    mode = st.radio(
        "Data source",
        ["Live Suricata EVE", "Upload EVE JSON", "Demo events"]
    )

    eve_path = st.text_input(
        "EVE JSON path",
        os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
    )

    uploaded = (
        st.file_uploader("Upload EVE JSON", type=["json", "log", "txt"])
        if mode == "Upload EVE JSON"
        else None
    )

    max_events = st.slider(
        "Recent events to display",
        min_value=100,
        max_value=10000,
        value=500,
        step=100
    )

    refresh = st.checkbox(
        "Auto-refresh dashboard",
        value=(mode == "Live Suricata EVE")
    )

    interval = st.selectbox(
        "Refresh interval (seconds)",
        [2, 5, 10, 15, 30],
        index=1,
        disabled=not refresh
    )

if refresh:
    st_autorefresh(interval=interval * 1000, key="nids_refresh")


# --------------------------------------------------
# LOAD EVENTS
# --------------------------------------------------

live_alerts = []

if mode == "Demo events":
    events = load_events(demo=True, limit=max_events)
    source = "DEMO FIXTURES — synthetic test data"

elif mode == "Upload EVE JSON":
    events = (
        load_events(
            raw_text=uploaded.getvalue().decode(
                "utf-8", errors="replace"
            ),
            limit=max_events
        )
        if uploaded
        else []
    )
    source = f"Uploaded: {uploaded.name}" if uploaded else "Waiting for upload"

else:
    events, live_alerts = read_new_eve_events(
        eve_path,
        buffer_limit=max_events,
        alert_limit=200
    )
    source = f"{eve_path} — incremental live monitoring"


# --------------------------------------------------
# BEHAVIOURAL DETECTION ENGINE
# --------------------------------------------------

behavior_alerts = []

if mode == "Live Suricata EVE":

    # Preserve detector state across Streamlit refreshes.
    if "behavior_detector" not in st.session_state:
        st.session_state.behavior_detector = BehavioralDetector(
            port_threshold=15,
            window_seconds=60
        )

    if "behavior_alerts" not in st.session_state:
        st.session_state.behavior_alerts = []

    # Analyse the rolling network-event buffer.
    new_behavior_alerts = (
        st.session_state.behavior_detector
        .detect_port_scans(events)
    )

    # Keep behavioural detections separately from 60-day incident records.
    for detection in new_behavior_alerts:
        try:
            nids_db.save_behavioral_detection(detection)
        except Exception as exc:
            st.warning(f"Behavioural detection persistence unavailable: {exc}")

    # Retain detected behavioural incidents.
    st.session_state.behavior_alerts.extend(
        new_behavior_alerts
    )

    st.session_state.behavior_alerts = (
        st.session_state.behavior_alerts[-100:]
    )

    behavior_alerts = st.session_state.behavior_alerts

    st.divider()
    st.header("Behavioural Detection")

    st.metric(
        "Behavioural detections",
        len(behavior_alerts)
    )

    if behavior_alerts:
        behavior_df = pd.DataFrame(behavior_alerts)

        st.dataframe(
            behavior_df[
                [
                    "detection_type",
                    "severity",
                    "source_ip",
                    "destination_ip",
                    "unique_destination_ports",
                    "window_seconds",
                    "description"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

        with st.expander("Behavioural detection investigation"):
            for index, detection in enumerate(behavior_alerts):
                st.markdown(
                    f"**Detection {index + 1}: "
                    f"{detection['detection_type']}**"
                )
                st.write(detection["description"])
                st.write(
                    "Recommended action:",
                    detection["recommended_action"]
                )
    else:
        st.info(
            "No suspicious port-scan behaviour detected "
            "in the current monitoring session."
        )


# --------------------------------------------------
# NETWORK ACTIVITY MONITOR
# --------------------------------------------------

st.header(":globe_with_meridians: Live Network Activity")

event_types = [
    str(event.get("event_type", "unknown")).lower()
    for event in events
]

event_counts = pd.Series(event_types).value_counts()

total_events = len(events)
dns_count = int(event_counts.get("dns", 0))
tls_count = int(event_counts.get("tls", 0))
http_count = int(event_counts.get("http", 0))
flow_count = int(event_counts.get("flow", 0))
alert_count = int(event_counts.get("alert", 0))
other_count = total_events - (
    dns_count + tls_count + http_count + flow_count + alert_count
)

m1, m2, m3, m4, m5, m6 = st.columns(6)

if mode == "Live Suricata EVE":
    totals = st.session_state.get("event_totals", {})
    total_session = sum(totals.values())

    dns_total = totals.get("dns", 0)
    tls_total = totals.get("tls", 0)
    http_total = totals.get("http", 0)
    flow_total = totals.get("flow", 0)
    alert_total = st.session_state.get("session_alert_total", 0)

    m1.metric("Session events", total_session)
    m2.metric("DNS total", dns_total)
    m3.metric("TLS total", tls_total)
    m4.metric("HTTP total", http_total)
    m5.metric("Flow total", flow_total)
    m6.metric("Session alerts", alert_total)

else:
    m1.metric("Total events", total_events)
    m2.metric("DNS events", dns_count)
    m3.metric("TLS events", tls_count)
    m4.metric("HTTP events", http_count)
    m5.metric("Flow events", flow_count)
    m6.metric("Security alerts", alert_count)
    
if mode == "Live Suricata EVE":
    last_time = st.session_state.get("last_event_timestamp")
    received = st.session_state.get("last_event_received")

    if received:
        seconds_ago = (
            datetime.now().astimezone() - received
        ).total_seconds()

        if seconds_ago <= 15:
            st.success("🟢 Sensor active — events recently received")
        else:
            st.warning("🟡 Waiting for new network events")


    else:
        st.info("Waiting for the first new event...")

    st.caption(f"Latest event timestamp: {last_time or 'No new event yet'}")

if other_count:
    st.caption(f"Other event types: {other_count}")

if events:
    activity_chart = pd.DataFrame(
        {"Events": event_counts}
    )

    st.subheader("Network event distribution")
    st.bar_chart(activity_chart)

    activity_rows = []

    for event in reversed(events[-max_events:]):
        alert = event.get("alert") or {}

        activity_rows.append({
    "Timestamp": str(event.get("timestamp") or "—"),
    "Event type": str(event.get("event_type", "unknown")).upper(),
    "Source IP": str(event.get("src_ip") or "—"),
    "Source port": str(event.get("src_port") or "—"),
    "Destination IP": str(event.get("dest_ip") or "—"),
    "Destination port": str(event.get("dest_port") or "—"),
    "Protocol": str(event.get("proto") or "—"),
    "Signature": str(alert.get("signature") or "—")
})

    activity_df = pd.DataFrame(activity_rows)

    st.subheader("Recent network events")

    available_types = sorted(
        activity_df["Event type"].unique().tolist()
    )

    selected_types = st.multiselect(
        "Filter event types",
        available_types,
        default=available_types
    )

    filtered_activity = activity_df[
        activity_df["Event type"].isin(selected_types)
    ]

    st.dataframe(
        filtered_activity,
        use_container_width=True,
        hide_index=True
    )

else:
    st.info(
        "No network events loaded. Check the EVE JSON source "
        "and keep Suricata running."
    )

# --------------------------------------------------
# SECURITY ALERT PROCESSING
# --------------------------------------------------

if mode == "Live Suricata EVE":
    alerts = live_alerts
else:
    alerts = [
        event for event in events
        if event.get("event_type") == "alert" or event.get("alert")
    ]

# Cache triage results across Streamlit reruns so the same alert is not
# repeatedly sent to the LLM (which would waste time and API quota).
triage_cache = st.session_state.setdefault("nids_triage_cache", {})
items = [enrich_alert(event, cache=triage_cache) for event in alerts]
llm_count = sum(
    item.get("triage", {}).get("provider") == "gemini-api"
    for item in items
)
fallback_count = len(items) - llm_count

st.divider()
st.header(":rotating_light: Security Alert Monitoring")
if alerts:
    if llm_count > 0:
        st.success(
            f"Gemini AI enrichment active for {llm_count} alert(s); "
            f"local fallback used for {fallback_count}."
        )
    else:
        if os.getenv("GEMINI_API_KEY"):
            st.warning(
                "Gemini API key detected, but no alerts were enriched by Gemini. "
                "Check the API response."
            )
        else:
            st.info(
                "Local rule-based triage is active. "
                "Configure GEMINI_API_KEY to enable AI enrichment."
            )

if not alerts:
    st.info(
        "No security alerts detected in the current event set. "
        "Network monitoring is still active."
    )

else:
    rows = []

    for i, item in enumerate(items):
        raw = item.get("raw", {})
        triage = item.get("triage", {})
        alert = item.get("alert", {})

        rows.append({
            "Index": i,
            "Timestamp": item.get("timestamp") or "",
            "Priority": triage.get("severity", "LOW"),
            "Suricata severity": alert.get("severity", "—"),
            "Signature": alert.get("signature", "Unknown"),
            "Source IP": item.get("src_ip", "—"),
            "Destination IP": item.get("dest_ip", "—"),
            "Destination port": raw.get("dest_port", "—"),
            "Protocol": item.get("proto", "—"),
            "Triage provider": triage.get("provider", "unknown")
        })

    df = pd.DataFrame(rows)

    high = int((df["Priority"] == "HIGH").sum())
    medium = int((df["Priority"] == "MEDIUM").sum())
    low = int((df["Priority"] == "LOW").sum())

    m1, m2, m3, m4 = st.columns(4)

    m1.metric("Total alerts", len(df))
    m2.metric("High priority", high)
    m3.metric("Medium priority", medium)
    m4.metric("Low priority", low)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Triage priority distribution")
        st.bar_chart(
            pd.DataFrame(
                {"Alerts": [high, medium, low]},
                index=["HIGH", "MEDIUM", "LOW"]
            )
        )

    with col2:
        st.subheader("Top alert signatures")
        st.bar_chart(df["Signature"].value_counts().head(6))

    st.subheader("Alert queue")

    priorities = st.multiselect(
        "Filter by triage priority",
        ["HIGH", "MEDIUM", "LOW"],
        ["HIGH", "MEDIUM", "LOW"]
    )

    st.dataframe(
        df[df.Priority.isin(priorities)].drop(columns=["Index"]),
        use_container_width=True,
        hide_index=True
    )

    st.subheader("Alert investigation")

    options = [
        f"{i} | {r['Priority']} | {r['Signature']} | "
        f"{r['Source IP']} → {r['Destination IP']}"
        for i, r in df.iterrows()
    ]

    selection = st.selectbox("Select an alert", options)
    selected_index = int(selection.split(" | ", 1)[0])

    item = items[selected_index]

    raw = item.get("raw", {})
    alert = item.get("alert", {})
    triage = item.get("triage", {})

    left, right = st.columns(2)

    with left:
        st.markdown("**Analyst summary**")
        st.write(triage.get("summary", "—"))

        st.markdown("**Recommended next action**")
        st.write(triage.get("recommended_action", "—"))

        st.markdown("**Triage rationale**")
        st.write(triage.get("reason", "—"))

        st.caption(
            "Triage provider: " +
            str(triage.get("provider", "unknown"))
        )

    with right:
        st.markdown("**Network context**")

        st.json({
            "timestamp": raw.get("timestamp"),
            "interface": raw.get("in_iface"),
            "source": (
                f"{raw.get('src_ip', '—')}:"
                f"{raw.get('src_port', '—')}"
            ),
            "destination": (
                f"{raw.get('dest_ip', '—')}:"
                f"{raw.get('dest_port', '—')}"
            ),
            "protocol": raw.get("proto"),
            "Suricata signature": alert.get("signature"),
            "signature_id": alert.get("signature_id"),
            "Suricata severity": alert.get("severity"),
            "triage priority": triage.get("severity")
        })

    with st.expander("View original EVE JSON event"):
        st.json(raw)

    st.download_button(
        ":arrow_down: Export enriched alerts (JSON)",
        json.dumps(items, indent=2),
        file_name="nids_enriched_alerts.json",
        mime="application/json"
    )



# --------------------------------------------------
# INCIDENT MANAGEMENT
# --------------------------------------------------

def incident_fingerprint(kind, source_ip, destination_ip, signature):
    raw_key = "|".join([
        str(kind), str(source_ip), str(destination_ip), str(signature)
    ])
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]


def upsert_incident(kind, severity, source_ip, destination_ip,
                    signature, timestamp, description, evidence,
                    recommended_action):
    """Create or update a deduplicated incident in this dashboard session."""
    if "nids_incidents" not in st.session_state:
        restored_incidents = nids_db.get_incidents()
        st.session_state["nids_incidents"] = {
            incident_fingerprint(
                record.get("detection_type"), record.get("source_ip"),
                record.get("destination_ip"), record.get("signature")
            ): record
            for record in restored_incidents
        }
    incidents = st.session_state["nids_incidents"]
    fingerprint = incident_fingerprint(
        kind, source_ip, destination_ip, signature
    )

    severity = str(severity).upper()
    risk_by_severity = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 25}
    risk_score = risk_by_severity.get(severity, 25)

    if fingerprint not in incidents:
        incidents[fingerprint] = {
            "incident_id": f"INC-{fingerprint.upper()}",
            "detection_type": kind,
            "severity": severity,
            "risk_score": risk_score,
            "source_ip": source_ip or "Unknown",
            "destination_ip": destination_ip or "Unknown",
            "signature": signature or kind,
            "first_seen": timestamp or datetime.now().astimezone().isoformat(),
            "last_seen": timestamp or datetime.now().astimezone().isoformat(),
            "event_count": 0,
            "description": description or "Security detection recorded.",
            "recommended_action": recommended_action or "Review the evidence.",
            "evidence": [],
            "status": "Open",
            "analyst_notes": ""
        }

    incident = incidents[fingerprint]
    is_new_evidence = bool(evidence) and evidence not in incident["evidence"]
    if is_new_evidence or incident["event_count"] == 0:
        incident["event_count"] += 1
    incident["last_seen"] = timestamp or datetime.now().astimezone().isoformat()
    incident["risk_score"] = max(incident["risk_score"], risk_score)
    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(severity, 0) > order.get(incident["severity"], 0):
            incident["severity"] = severity

    if evidence and evidence not in incident["evidence"]:
        incident["evidence"].append(evidence)
        incident["evidence"] = incident["evidence"][-20:]

    # Persist incident and evidence on every upsert.
    incident["fingerprint"] = fingerprint
    try:
        nids_db.save_incident(incident)
    except Exception as exc:
        st.warning(f"SQLite incident persistence unavailable: {exc}")


# Convert behavioural detections into incidents.
for detection in behavior_alerts:
    upsert_incident(
        kind=detection.get("detection_type", "BEHAVIOURAL_DETECTION"),
        severity=detection.get("severity", "MEDIUM"),
        source_ip=detection.get("source_ip"),
        destination_ip=detection.get("destination_ip"),
        signature=detection.get("detection_type", "Behavioural detection"),
        timestamp=detection.get("first_seen"),
        description=detection.get("description"),
        evidence=(
            f"{detection.get('unique_destination_ports', '—')} unique "
            f"destination ports in {detection.get('window_seconds', '—')} seconds"
        ),
        recommended_action=detection.get("recommended_action")
    )

# Convert Suricata alerts into incidents.
for item in items:
    raw = item.get("raw", {})
    alert = item.get("alert", {})
    triage = item.get("triage", {})
    upsert_incident(
        kind="SURICATA_ALERT",
        severity=triage.get("severity", "LOW"),
        source_ip=raw.get("src_ip"),
        destination_ip=raw.get("dest_ip"),
        signature=alert.get("signature", "Unknown Suricata alert"),
        timestamp=item.get("timestamp"),
        description=triage.get("summary", alert.get("signature", "Suricata alert")),
        evidence=(
            f"{item.get('timestamp', '—')} | "
            f"SID={alert.get('signature_id', '—')}; "
            f"Suricata severity={alert.get('severity', '—')}; "
            f"protocol={raw.get('proto', '—')}"
        ),
        recommended_action=triage.get("recommended_action")
    )

st.divider()
st.header("🗂️ Incident Management")

if "nids_incidents" not in st.session_state:
    restored_incidents = nids_db.get_incidents()
    st.session_state["nids_incidents"] = {
        incident_fingerprint(
            record.get("detection_type"), record.get("source_ip"),
            record.get("destination_ip"), record.get("signature")
        ): record
        for record in restored_incidents
    }
incident_store = st.session_state["nids_incidents"]
incident_records = list(incident_store.values())

if not incident_records:
    st.info(
        "No incidents have been created yet. Incidents will appear when "
        "Suricata alerts or behavioural detections are generated."
    )
else:
    incident_df = pd.DataFrame([
        {
            "Incident ID": x["incident_id"],
            "Type": x["detection_type"],
            "Severity": x["severity"],
            "Risk score": x["risk_score"],
            "Source IP": x["source_ip"],
            "Destination IP": x["destination_ip"],
            "Events": x["event_count"],
            "Status": x["status"],
            "Last seen": x["last_seen"]
        }
        for x in incident_records
    ])

    open_count = sum(x["status"] == "Open" for x in incident_records)
    investigating_count = sum(
        x["status"] == "Investigating" for x in incident_records
    )
    resolved_count = sum(x["status"] == "Resolved" for x in incident_records)

    ic1, ic2, ic3, ic4 = st.columns(4)
    ic1.metric("Total incidents", len(incident_records))
    ic2.metric("Open", open_count)
    ic3.metric("Investigating", investigating_count)
    ic4.metric("Resolved", resolved_count)

    st.subheader("Incident register")
    st.dataframe(
        incident_df.sort_values(
            ["Risk score", "Last seen"], ascending=[False, False]
        ),
        use_container_width=True,
        hide_index=True
    )

    incident_options = {
        f"{x['incident_id']} | {x['severity']} | {x['signature']}": x["incident_id"]
        for x in sorted(
            incident_records,
            key=lambda record: record["risk_score"],
            reverse=True
        )
    }
    selected_label = st.selectbox(
        "Investigate incident",
        list(incident_options.keys()),
        key="incident_selector"
    )
    selected_id = incident_options[selected_label]
    selected_incident = next(
        x for x in incident_records if x["incident_id"] == selected_id
    )
    selected_key = next(
        key for key, value in incident_store.items()
        if value["incident_id"] == selected_id
    )

    st.markdown(f"**{selected_incident['incident_id']}**")
    st.write(selected_incident["description"])
    st.write(
        f"Risk score: **{selected_incident['risk_score']}/100** "
        f"— severity: **{selected_incident['severity']}**"
    )
    st.write("Recommended action:", selected_incident["recommended_action"])

    with st.expander("Incident evidence timeline", expanded=True):
        st.write("First seen:", selected_incident["first_seen"])
        st.write("Last seen:", selected_incident["last_seen"])
        st.write("Observed event count:", selected_incident["event_count"])
        for evidence_item in selected_incident["evidence"]:
            st.markdown(f"- {evidence_item}")

    status_value = st.selectbox(
        "Incident status",
        ["Open", "Investigating", "Resolved"],
        index=["Open", "Investigating", "Resolved"].index(
            selected_incident["status"]
        ),
        key=f"incident_status_{selected_id}"
    )
    notes_value = st.text_area(
        "Analyst notes",
        value=selected_incident.get("analyst_notes", ""),
        key=f"incident_notes_{selected_id}",
        placeholder="Record investigation findings, containment steps, or closure rationale..."
    )
    if st.button("Save incident updates", key=f"save_incident_{selected_id}"):
        incident_store[selected_key]["status"] = status_value
        incident_store[selected_key]["analyst_notes"] = notes_value
        try:
            nids_db.update_incident(selected_id, status_value, notes_value)
            st.success("Incident status and analyst notes saved to SQLite.")
        except Exception as exc:
            st.error(f"Could not persist incident updates: {exc}")

    st.download_button(
        "Export incident register (JSON)",
        json.dumps(incident_records, indent=2),
        file_name="nids_incident_register.json",
        mime="application/json"
    )

    st.caption(
        f"Persistent incident register: SQLite ({nids_db.db_path}). "
        "Incident evidence, status changes and analyst notes are stored locally."
    )


# --------------------------------------------------
# STATUS
# --------------------------------------------------

if mode == "Demo events":
    st.warning(
        "Demo fixtures are synthetic UI test data, "
        "not live network detections."
    )
elif mode == "Live Suricata EVE":
    st.success(
        f"Monitoring EVE source: {eve_path}. "
        f"Loaded {total_events} events and {alert_count} alerts."
    )

