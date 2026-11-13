from dotenv import load_dotenv
load_dotenv()
import json
import hashlib
import os
from datetime import datetime

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from nids_core import load_events, enrich_alert, enrich_incident

from behavior_engine import BehavioralDetector
from incident_engine import IncidentCorrelator
from storage import NIDSStorage

# Streamlit requires page configuration before any other Streamlit command.
st.set_page_config(
    page_title="AI-Enhanced NIDS",
    page_icon=":shield:",
    layout="wide"
)

# Fixed display window for this academic demonstration; retention is independent.
DISPLAY_EVENT_LIMIT = 500

# Shared local database for dashboard persistence.
nids_db = NIDSStorage()

if not st.session_state.get("nids_retention_applied", False):
    try:
        nids_db.apply_retention(routine_event_cap=20000)
        st.session_state["nids_retention_applied"] = True
    except Exception as exc:
        st.warning(f"Database retention cleanup could not run: {exc}")

def read_new_eve_events(path, buffer_limit=DISPLAY_EVENT_LIMIT, alert_limit=200):
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

    # Reload the fixed recent display window from SQLite. Ingestion remains
    # incremental; this query does not reread the EVE file or duplicate records.
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

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --nids-bg: #101923;
        --nids-surface: #1B2836;
        --nids-elevated: #29394B;
        --nids-muted: #60758B;
        --nids-text: #CBD5E1;
        --nids-bright: #F1F5F9;
        --nids-border: rgba(148, 163, 184, 0.16);
        --nids-accent: #8FA6BC;
    }

    html, body, [class*="stApp"] {
        font-family: 'Inter', 'Segoe UI', Roboto, sans-serif;
    }
    .stApp { background: var(--nids-bg); color: var(--nids-text); }
    [data-testid="stHeader"] { background: rgba(16, 25, 35, 0.92); }
    [data-testid="stToolbar"] { right: 1rem; }
    [data-testid="stSidebar"] {
        background: #131F2B;
        border-right: 1px solid var(--nids-border);
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: var(--nids-text);
    }
    h1, h2, h3, h4 {
        color: var(--nids-bright) !important;
        letter-spacing: -0.025em;
        font-weight: 600 !important;
    }
    h1 { font-size: clamp(1.65rem, 2.2vw, 2.15rem) !important; }
    h2 { font-size: 1.35rem !important; }
    h3 { font-size: 1.08rem !important; }
    p, label, .stCaption, [data-testid="stMarkdownContainer"] {
        color: var(--nids-text);
    }
    [data-testid="stMetric"] {
        background: var(--nids-surface);
        border: 1px solid var(--nids-border);
        border-radius: 10px;
        padding: 14px 16px;
    }
    [data-testid="stMetricLabel"] { color: #9FB0C1 !important; }
    [data-testid="stMetricValue"] {
        color: var(--nids-bright) !important;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
    }
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid var(--nids-border);
        border-radius: 9px;
        overflow: hidden;
    }
    [data-testid="stExpander"] {
        background: rgba(27, 40, 54, 0.58);
        border: 1px solid var(--nids-border);
        border-radius: 9px;
    }
    [data-testid="stTextInput"] input,
    [data-testid="stTextArea"] textarea,
    [data-testid="stSelectbox"] [data-baseweb="select"],
    [data-testid="stMultiSelect"] [data-baseweb="select"] {
        background: var(--nids-surface);
        border-color: var(--nids-border);
        border-radius: 7px;
    }
    .stButton > button, .stDownloadButton > button {
        border: 1px solid rgba(143, 166, 188, 0.35);
        border-radius: 7px;
        background: #29394B;
        color: var(--nids-bright);
        font-weight: 500;
        transition: background 120ms ease, border-color 120ms ease;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        background: #35495E;
        border-color: #8FA6BC;
        color: #FFFFFF;
    }
    [data-testid="stAlert"] { border-radius: 8px; }
    hr { border-color: var(--nids-border) !important; }
    code, pre, [data-testid="stCode"] {
        font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace !important;
        font-size: 0.88em;
    }
    [data-testid="stJson"] {
        background: rgba(27, 40, 54, 0.72);
        border: 1px solid var(--nids-border);
        border-radius: 8px;
        padding: 10px;
    }
    /* Keep status colours reserved for actual operational state. */
    [data-testid="stStatusWidget"] { color: var(--nids-text); }
    @media (max-width: 768px) {
        [data-testid="stMetric"] { padding: 10px 12px; }
        h1 { font-size: 1.55rem !important; }
    }
    </style>
""", unsafe_allow_html=True)

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

    max_events = DISPLAY_EVENT_LIMIT

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

        st.markdown("**Threat context**")
        st.write(triage.get("threat_context", "Not available."))

        st.markdown("**Potential impact**")
        st.write(triage.get("potential_impact", "Not assessed."))

        st.markdown("**Investigation playbook**")
        investigation_steps = triage.get("investigation_steps", [])
        if investigation_steps:
            for step_no, step in enumerate(investigation_steps, start=1):
                st.write(f"{step_no}. {step}")
        else:
            st.write("No investigation steps returned.")

        st.markdown("**Response recommendations**")
        response_recommendations = triage.get("response_recommendations", [])
        if response_recommendations:
            for recommendation in response_recommendations:
                st.write(f"• {recommendation}")
        else:
            st.write(triage.get("recommended_action", "—"))

        st.markdown("**False-positive considerations**")
        false_positives = triage.get("false_positive_considerations", [])
        if false_positives:
            for consideration in false_positives:
                st.write(f"• {consideration}")
        else:
            st.write("Not assessed.")

        st.markdown("**MITRE ATT&CK mapping (suggested)**")
        mitre_items = triage.get("mitre_attack", [])
        if mitre_items:
            for technique in mitre_items:
                st.write(
                    f"{technique.get('technique_id', '')} — "
                    f"{technique.get('technique', '')} "
                    f"({technique.get('tactic', 'Tactic not specified')})"
                )
                if technique.get("rationale"):
                    st.caption(technique["rationale"])
        else:
            st.write("No technique mapping is sufficiently supported by the available evidence.")

        st.markdown("**Analysis confidence**")
        st.write(
            f"{triage.get('confidence', 'LOW')} — "
            f"{triage.get('confidence_reason', 'Confidence not provided.') }"
        )

        with st.expander("Evidence used and analysis limitations"):
            st.markdown("**Evidence considered**")
            for evidence in triage.get("evidence_used", []):
                st.write(f"• {evidence}")
            st.markdown("**Limitations**")
            for limitation in triage.get("limitations", []):
                st.write(f"• {limitation}")

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
                    recommended_action, observed_event_count=None,
                    risk_score_override=None, risk_factors=None,
                    risk_scoring_method=None, risk_score_limitations=None):
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
    risk_score = (
        max(0, min(100, int(risk_score_override)))
        if risk_score_override is not None
        else risk_by_severity.get(severity, 25)
    )

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
            "analyst_notes": "",
            "risk_factors": [],
            "risk_scoring_method": None,
            "risk_score_limitations": []
        }

    incident = incidents[fingerprint]
    is_new_evidence = bool(evidence) and evidence not in incident["evidence"]
    if is_new_evidence or incident["event_count"] == 0:
        incident["event_count"] += 1
    incident["last_seen"] = timestamp or datetime.now().astimezone().isoformat()
    incident["risk_score"] = (
        risk_score if risk_score_override is not None
        else max(incident["risk_score"], risk_score)
    )
    if risk_factors is not None:
        incident["risk_factors"] = risk_factors
    if risk_scoring_method is not None:
        incident["risk_scoring_method"] = risk_scoring_method
    if risk_score_limitations is not None:
        incident["risk_score_limitations"] = risk_score_limitations
    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(severity, 0) > order.get(incident["severity"], 0):
            incident["severity"] = severity

    if evidence and evidence not in incident["evidence"]:
        incident["evidence"].append(evidence)
        incident["evidence"] = incident["evidence"][-20:]
    if observed_event_count is not None:
        incident["event_count"] = max(incident["event_count"], int(observed_event_count))

    # Persist incident and evidence on every upsert.
    incident["fingerprint"] = fingerprint
    try:
        nids_db.save_incident(incident)
    except Exception as exc:
        st.warning(f"SQLite incident persistence unavailable: {exc}")


# Correlate Suricata and behavioural detections before placing them in the
# existing persistent incident register. The correlator is session-scoped so
# Streamlit reruns do not duplicate evidence. Existing incident UI/status/notes
# remain unchanged.
if "nids_correlator" not in st.session_state:
    st.session_state["nids_correlator"] = IncidentCorrelator(correlation_window=300)
correlator = st.session_state["nids_correlator"]
correlated_incidents = correlator.ingest(alerts, behavior_alerts)

for correlated in correlated_incidents:
    risk_level = correlated.get("risk_level", "LOW")
    severity = "CRITICAL" if risk_level == "CRITICAL" else risk_level
    destinations = correlated.get("destinations") or ["Unknown"]
    destination_text = ", ".join(str(value) for value in destinations[:8])
    evidence_text = json.dumps(correlated.get("evidence", [])[-20:], ensure_ascii=False)
    upsert_incident(
        kind="CORRELATED_ACTIVITY",
        severity=severity,
        source_ip=correlated.get("source_ip"),
        destination_ip=destination_text,
        signature=f"Correlated activity {correlated.get('incident_id', '')}",
        timestamp=correlated.get("last_seen"),
        description=(
            f"Correlated {correlated.get('event_count', 0)} detection(s) from "
            f"{correlated.get('source_ip', 'unknown source')} across "
            f"{len(destinations)} destination(s) within the configured "
            f"{correlator.correlation_window}-second correlation window."
        ),
        evidence=evidence_text,
        recommended_action=correlated.get("recommended_action"),
        observed_event_count=correlated.get("event_count", 0),
        risk_score_override=correlated.get("risk_score"),
        risk_factors=correlated.get("risk_factors", []),
        risk_scoring_method=correlated.get("risk_scoring_method"),
        risk_score_limitations=correlated.get("risk_score_limitations", [])
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
    factors = selected_incident.get("risk_factors") or []
    if factors:
        st.markdown("**Why this risk score?**")
        st.dataframe(
            pd.DataFrame([
                {
                    "Factor": item.get("name", "Unknown"),
                    "Points": item.get("points", 0),
                    "Maximum": item.get("maximum", 0),
                    "Reason": item.get("explanation", "")
                } for item in factors
            ]),
            use_container_width=True,
            hide_index=True
        )
        limitations = selected_incident.get("risk_score_limitations") or []
        if limitations:
            with st.expander("Risk score assumptions and limitations"):
                for limitation in limitations:
                    st.markdown(f"- {limitation}")
    else:
        st.caption(
            "No factor breakdown is stored for this incident yet. "
            "New correlated evidence will populate the explainable score."
        )
    st.write("Recommended action:", selected_incident["recommended_action"])

    st.subheader("AI incident investigation")
    incident_ai_cache = st.session_state.setdefault("nids_incident_ai_cache", {})
    refresh_incident_ai = st.button("Re-run AI incident analysis", key=f"refresh_incident_ai_{selected_id}")
    with st.spinner("Preparing evidence-based incident analysis..."):
        incident_analysis = enrich_incident(
            selected_incident, cache=incident_ai_cache, force_refresh=refresh_incident_ai
        )
    st.caption(
        f"Analysis provider: {incident_analysis.get('provider', 'unknown')} • "
        f"Confidence: {incident_analysis.get('confidence', 'LOW')}"
    )
    st.markdown("**Incident assessment**")
    st.write(incident_analysis.get("summary", "No summary available."))
    st.markdown("**Why these events matter**")
    st.write(incident_analysis.get("reason", "No rationale available."))
    st.markdown("**Threat context and potential impact**")
    st.write(incident_analysis.get("threat_context", "Not assessed."))
    st.write(incident_analysis.get("potential_impact", "Not assessed."))
    with st.expander("Investigation playbook", expanded=True):
        for step in incident_analysis.get("investigation_steps", []):
            st.markdown(f"- {step}")
    with st.expander("Response recommendations"):
        for step in incident_analysis.get("response_recommendations", []):
            st.markdown(f"- {step}")
    with st.expander("False-positive considerations"):
        for item in incident_analysis.get("false_positive_considerations", []):
            st.markdown(f"- {item}")
    with st.expander("MITRE ATT&CK mapping and evidence limitations"):
        if incident_analysis.get("mitre_attack"):
            st.json(incident_analysis["mitre_attack"])
        else:
            st.caption("No ATT&CK technique was mapped from the available evidence.")
        st.write("Confidence rationale:", incident_analysis.get("confidence_reason", "Not supplied."))
        st.write("Evidence considered:")
        st.json(incident_analysis.get("evidence_used", []))
        st.write("Limitations:")
        st.json(incident_analysis.get("limitations", []))

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
    st.download_button(
        "Export incident register (CSV)",
        incident_df.to_csv(index=False),
        file_name="nids_incident_register.csv",
        mime="text/csv"
    )

    report_lines = [
        "# NIDS Executive Security Summary",
        "",
        f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Data source: {source}",
        f"Events in current view: {total_events}",
        f"Alerts in current view: {len(alerts)}",
        f"Incidents: {len(incident_records)}",
        f"Open: {open_count} | Investigating: {investigating_count} | Resolved: {resolved_count}",
        "",
        "## Highest-priority incidents",
    ]
    for record in sorted(incident_records, key=lambda x: x.get("risk_score", 0), reverse=True)[:10]:
        report_lines.append(
            f"- {record.get('incident_id')} | {record.get('severity')} | "
            f"Risk {record.get('risk_score')}/100 | {record.get('signature')} | "
            f"Status: {record.get('status')}"
        )
    report_lines.extend([
        "",
        "## Interpretation",
        "This report summarises detections and triage recommendations. "
        "A Suricata alert or AI triage result is not, by itself, proof of compromise. "
        "Validate findings against host, authentication and network evidence.",
    ])
    st.download_button(
        "Download executive summary (Markdown)",
        "\n".join(report_lines),
        file_name="nids_executive_summary.md",
        mime="text/markdown"
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

