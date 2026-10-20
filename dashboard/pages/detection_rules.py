"""Detection Rules page documenting active detection logic and thresholds."""
import streamlit as st
from dashboard.components.metrics import render_severity_badge
from app.detection.engine import DetectionEngine


def render_detection_rules():
    st.markdown("### 📜 NIDS Detection Rules & Engine Specifications")
    st.caption("Active detection algorithms, configurable thresholds, correlation windows, and forensic evidence structures.")

    engine = DetectionEngine()
    rules_info = engine.get_rules_info()

    detailed_specs = {
        "RULE-001": {
            "example_trigger": "Attacker IP 10.0.0.50 sends SYN packets to ports 20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445 on target 192.168.1.10 within 10 seconds.",
            "detection_logic": "Aggregates events in sliding window T (default 10s). Extracts destination ports grouped by (source_ip, destination_ip). Fired when count(DISTINCT destination_port) >= Threshold (default 10).",
            "evidence_produced": '{\n  "unique_ports_count": 13,\n  "ports": [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080],\n  "threshold": 10,\n  "window_seconds": 10\n}',
            "mitigation": "Temporary IP block at firewall, verify whether IP belongs to authorized security scanner, audit target services."
        },
        "RULE-002": {
            "example_trigger": "Host 10.0.0.100 sends 15 repeated TCP SYN connections to 192.168.1.50 port 22 (SSH) in 30 seconds.",
            "detection_logic": "Tracks connection attempts in sliding window T (default 30s) grouped by (source_ip, destination_ip, destination_port). Fired when connection_count >= Threshold (default 10).",
            "evidence_produced": '{\n  "connection_count": 15,\n  "attempt_count": 15,\n  "threshold": 10,\n  "window_seconds": 30\n}',
            "mitigation": "Deploy Fail2Ban or host rate limiting, enforce SSH public-key authentication, verify authentication server logs."
        },
        "RULE-003": {
            "example_trigger": "Compromised internal machine 10.0.0.200 floods 60 packets across random subnet addresses in 10 seconds.",
            "detection_logic": "Tracks total outbound connection attempts in sliding window T (default 10s) grouped by source_ip. Fired when total_connections >= Threshold (default 50).",
            "evidence_produced": '{\n  "total_connections": 60,\n  "connection_count": 60,\n  "threshold": 50,\n  "window_seconds": 10\n}',
            "mitigation": "Isolate host on VLAN, conduct endpoint malware analysis, apply traffic egress rate limiting at switch."
        }
    }

    for r in rules_info:
        rid = str(r.get("code") or r.get("id"))
        spec = detailed_specs.get(rid, {})

        with st.expander(f"🛡️ [{rid}] {r['rule_name']}", expanded=True):
            col_left, col_right = st.columns([2, 1])
            with col_left:
                st.markdown(f"**Description:** {r['description']}")
                st.markdown(f"**Severity:** {render_severity_badge(r['severity'])}", unsafe_allow_html=True)
                st.markdown("**Detection Logic:**")
                st.code(spec.get("detection_logic", "Correlates events within sliding window against threshold."), language="text")
                st.markdown("**Example Attack Scenario:**")
                st.info(spec.get("example_trigger", "Simulated suspicious network flow."))

            with col_right:
                st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 0;'>CONFIGURED PARAMETERS</p>", unsafe_allow_html=True)
                st.markdown(f"- **Rule ID:** `{rid}`")
                st.markdown(f"- **Canonical Identifier:** `{r['rule_id']}`")
                st.markdown(f"- **Configured Threshold:** `{r['threshold']}`")
                st.markdown(f"- **Correlation Window:** `{r['time_window']} seconds`")
                st.markdown(f"- **Mitigation Action:** {r['recommendation']}")

            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 8px 0 4px 0;'>EVIDENCE PAYLOAD STRUCTURE</p>", unsafe_allow_html=True)
            st.code(spec.get("evidence_produced", "{}"), language="json")
