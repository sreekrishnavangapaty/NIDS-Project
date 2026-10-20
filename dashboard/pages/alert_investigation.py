"""Alert Investigation page for deep-dive SOC analysis."""
import streamlit as st
import pandas as pd
import json
import time
from dashboard.components.metrics import render_severity_badge, render_status_badge


def render_alert_investigation(repository):
    st.markdown("### 🔍 Alert Forensics & Incident Response")
    st.caption("Deep-dive forensic analysis, evidence verification, contributed network events, and triage workflow.")

    # 1. Fetch available alerts from SQLite
    alerts = repository.get_alerts(limit=200)
    if not alerts:
        st.info("No security alerts available in the database to investigate. Run Demo Mode or Live Monitoring first.")
        return

    df_alerts = pd.DataFrame(alerts)

    # 2. Alert Selection
    default_id = st.session_state.get('selected_alert_id', df_alerts['id'].iloc[0])
    if default_id not in df_alerts['id'].values:
        default_id = df_alerts['id'].iloc[0]

    selected_id = st.selectbox(
        "Select Security Alert for Forensics",
        df_alerts['id'].tolist(),
        index=df_alerts['id'].tolist().index(default_id),
        format_func=lambda x: f"Alert #{x} | [{df_alerts[df_alerts['id']==x]['severity'].values[0]}] {df_alerts[df_alerts['id']==x]['rule_name'].values[0]} — {df_alerts[df_alerts['id']==x]['source_ip'].values[0]} ({df_alerts[df_alerts['id']==x]['status'].values[0]})"
    )

    alert_row = df_alerts[df_alerts['id'] == selected_id].iloc[0]

    st.markdown("---")

    # Header with Badges
    col_hdr1, col_hdr2 = st.columns([3, 1], vertical_alignment="center")
    with col_hdr1:
        st.markdown(f"<h3 style='margin: 0; padding: 0;'>Alert #{alert_row['id']}: {alert_row.get('rule_name', 'Security Alert')}</h3>", unsafe_allow_html=True)
        st.caption(f"Triggered Rule ID: `{alert_row.get('rule_id', 'UNKNOWN')}`")
    with col_hdr2:
        st.markdown(
            f"<div style='text-align: right;'>"
            f"<b>Severity:</b> {render_severity_badge(alert_row.get('severity', 'MEDIUM'))}&nbsp;&nbsp;&nbsp;"
            f"<b>Status:</b> {render_status_badge(alert_row.get('status', 'NEW'))}"
            f"</div>",
            unsafe_allow_html=True
        )

    st.write("")

    # SECTION 1 & 2: ALERT DETAILS & NETWORK DETAILS
    c_meta1, c_meta2 = st.columns(2)
    with c_meta1:
        st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 0;'>📋 INCIDENT METADATA</p>", unsafe_allow_html=True)
        st.markdown(f"- **Alert ID:** `{alert_row['id']}`")
        st.markdown(f"- **Rule ID:** `{alert_row.get('rule_id', 'N/A')}`")
        st.markdown(f"- **Rule Name:** {alert_row.get('rule_name', 'N/A')}")
        st.markdown(f"- **Severity:** `{alert_row.get('severity', 'N/A')}`")
        st.markdown(f"- **Current Status:** `{alert_row.get('status', 'NEW')}`")
        st.markdown(f"- **Occurrence Count:** `{alert_row.get('occurrence_count', 1)}` time(s)")
        st.markdown(f"- **First Seen:** `{alert_row.get('first_seen', alert_row.get('timestamp', 'N/A'))}`")
        st.markdown(f"- **Last Seen:** `{alert_row.get('last_seen', alert_row.get('timestamp', 'N/A'))}`")

    with c_meta2:
        st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 0;'>🌐 NETWORK FLOW ATTRIBUTES</p>", unsafe_allow_html=True)
        st.markdown(f"- **Source IP:** `{alert_row.get('source_ip', 'N/A')}`")
        st.markdown(f"- **Destination IP:** `{alert_row.get('destination_ip', 'Any / Subnet')}`")
        st.markdown(f"- **Target Port:** `{alert_row.get('destination_port', 'Multiple / Variable')}`")
        st.markdown(f"- **Protocol:** `{alert_row.get('protocol', 'TCP')}`")
        st.markdown(f"- **Description:** {alert_row.get('description', 'N/A')}")

    st.markdown("---")

    # SECTION 3: DETECTION EVIDENCE
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 8px 0;'>🔬 DETECTION EVIDENCE & FORENSIC JUSTIFICATION</p>", unsafe_allow_html=True)
    raw_evidence = alert_row.get('evidence', '{}')
    evidence_dict = {}
    if isinstance(raw_evidence, str):
        try:
            evidence_dict = json.loads(raw_evidence)
        except Exception:
            evidence_dict = {"raw": raw_evidence}
    elif isinstance(raw_evidence, dict):
        evidence_dict = raw_evidence

    rule_id_str = str(alert_row.get('rule_id', ''))
    if "PORT_SCAN" in rule_id_str or "RULE-001" in rule_id_str:
        st.success(
            f"**Rule Port Scan Justification**: Source `{alert_row.get('source_ip')}` contacted **{evidence_dict.get('unique_ports_count', 'N/A')} unique destination ports** "
            f"within a **{evidence_dict.get('window_seconds', 10)}s time window**, exceeding the configured threshold of **{evidence_dict.get('threshold', 10)} ports**."
        )
        c_ev1, c_ev2 = st.columns(2)
        with c_ev1:
            st.metric("Unique Ports Scanned", evidence_dict.get('unique_ports_count', 0))
            st.metric("Detection Threshold", f"> {evidence_dict.get('threshold', 10)} ports")
        with c_ev2:
            st.markdown(f"**Target Destination Ports:**")
            ports_list = evidence_dict.get('ports', [])
            st.code(", ".join(str(p) for p in ports_list) if ports_list else "All targeted ports")

    elif "REPEATED" in rule_id_str or "RULE-002" in rule_id_str:
        st.warning(
            f"**Repeated Connection Justification**: Source `{alert_row.get('source_ip')}` made **{evidence_dict.get('connection_count', 'N/A')} connection attempts** "
            f"to destination `{alert_row.get('destination_ip')}:{alert_row.get('destination_port')}` within **{evidence_dict.get('window_seconds', 30)}s**, "
            f"exceeding the threshold of **{evidence_dict.get('threshold', 10)} attempts**."
        )
    elif "HIGH_RATE" in rule_id_str or "RULE-003" in rule_id_str:
        st.error(
            f"**High Connection Rate Justification**: Source `{alert_row.get('source_ip')}` generated **{evidence_dict.get('total_connections', evidence_dict.get('connection_count', 'N/A'))} connections** "
            f"within **{evidence_dict.get('window_seconds', 10)}s**, exceeding the threshold of **{evidence_dict.get('threshold', 50)}**."
        )

    with st.expander("View Raw Evidence JSON Payload", expanded=False):
        st.json(evidence_dict)

    st.markdown("---")

    # SECTION 4: RELATED CONTRIBUTING NETWORK EVENTS
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 6px 0;'>📡 CONTRIBUTING NETWORK EVENTS (INDIVIDUAL PACKETS)</p>", unsafe_allow_html=True)
    related_events = repository.get_events_for_alert(
        source_ip=alert_row['source_ip'],
        destination_ip=alert_row.get('destination_ip'),
        destination_port=alert_row.get('destination_port'),
        limit=50
    )
    if related_events:
        df_rel = pd.DataFrame(related_events)
        cols_show = [c for c in ['id', 'timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'tcp_flags', 'packet_size'] if c in df_rel.columns]
        st.dataframe(df_rel[cols_show], use_container_width=True, height=220)
    else:
        st.info("No matching individual packets found in event buffer for this alert.")

    st.markdown("---")

    # SECTION 5: INVESTIGATION GUIDANCE & DEFENSIVE SUGGESTIONS
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 6px 0;'>🛡️ DEFENSIVE TRIAGE GUIDANCE</p>", unsafe_allow_html=True)
    st.info("""
    **Recommended Analyst Action Checklist:**
    1. **Verify Source Authorization**: Determine if source IP `{src}` belongs to an authorized internal scanner, IT vulnerability scanner (e.g., Nessus, Qualys), or authorized administrative workstation.
    2. **Inspect Traffic Context**: Review the related network events above to verify whether connection attempts completed TCP 3-way handshakes (SYN-ACK / ACK) or were rejected with RST / ICMP unreachable.
    3. **Correlate Host Activity**: Check DNS queries, HTTP user agents, and authentication server logs corresponding to source `{src}`.
    4. **Evaluate Target Impact**: Check targeted host `{dst}` service health and verify no unauthorized accounts or remote code execution occurred.
    5. **Defensive Action (No automatic blocking)**: If confirmed malicious, add firewall rate-limit rule or temporary null-route at the perimeter firewall.
    """.format(src=alert_row.get('source_ip', 'N/A'), dst=alert_row.get('destination_ip', 'targets')))

    st.markdown("---")

    # SECTION 6: ALERT STATUS MANAGEMENT
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 6px 0;'>📝 INCIDENT STATUS LIFECYCLE MANAGEMENT</p>", unsafe_allow_html=True)
    c_stat1, c_stat2 = st.columns([2, 1], vertical_alignment="bottom")
    with c_stat1:
        new_status = st.selectbox(
            "Update Alert Status in SQLite",
            ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
            index=["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].index(alert_row.get('status', 'NEW'))
        )
    with c_stat2:
        if st.button("💾 Persist Status to SQLite", type="primary", use_container_width=True):
            success = repository.update_alert_status(alert_row['id'], new_status)
            if success:
                st.success(f"Status for Alert #{alert_row['id']} updated to `{new_status}` and persisted to SQLite!")
                time.sleep(0.4)
                st.rerun()
            else:
                st.error("Failed to update status in SQLite.")
