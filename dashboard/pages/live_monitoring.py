"""Live Packet Monitoring & Safe Demo Engine for NIDS."""
import streamlit as st
import pandas as pd
import time
from datetime import datetime

from app.detection.engine import DetectionEngine
from app.alerts.alert_manager import AlertManager
from app.features.extractor import FeatureExtractor
from app.capture.packet_capture import PacketCapture
from app.capture.packet_parser import parse_packet
from scripts.generate_demo_traffic import generate_events


def run_pipeline_for_events(events, repository):
    """Processes events through the REAL NIDS pipeline:
    Events -> Feature Extraction -> Detection Engine -> Alert Manager -> SQLite.
    """
    engine = DetectionEngine()
    alert_mgr = AlertManager(repository)

    alerts_created = 0
    rule_summary = {}

    for ev in events:
        repository.insert_event(ev)
        triggered = engine.process(ev)
        for a in triggered:
            aid = alert_mgr.process_alert(a)
            if aid:
                alerts_created += 1
                rname = str(getattr(a, 'rule_name', None) or getattr(a, 'rule_id', 'Alert'))
                rule_summary[rname] = rule_summary.get(rname, 0) + 1

    return alerts_created, rule_summary


def render_live_monitoring(repository):
    st.markdown("### 🛰️ Live Monitoring & Safe Traffic Simulator")
    st.caption("Capture real packets via Scapy or execute controlled synthetic attack scenarios through the complete detection pipeline.")

    tab_demo, tab_live = st.tabs(["🧪 Safe Demo Attack Simulator", "📡 Real Scapy Packet Capture"])

    # -------------------------------------------------------------
    # TAB 1: SAFE DEMO TRAFFIC SIMULATOR
    # -------------------------------------------------------------
    with tab_demo:
        st.info("💡 **Genuinely Functional Pipeline**: Demo traffic passes through the real packet parser, feature extraction, detection engine, alert deduplication, and SQLite database.")

        c1, c2, c3 = st.columns([2, 1, 1], vertical_alignment="bottom")
        with c1:
            scenario = st.selectbox(
                "Attack / Traffic Scenario",
                [
                    ("port_scan", "🚨 Port Scan (13 destination ports — triggers RULE-001)"),
                    ("repeated_connections", "⚠️ Repeated Connections (SSH brute force — triggers RULE-002)"),
                    ("high_rate", "🔥 High Connection Rate (Flood traffic — triggers RULE-003)"),
                    ("normal", "✅ Normal Network Traffic (HTTP/DNS/HTTPS — 0 alerts)"),
                    ("mixed", "🌐 Mixed Traffic (Normal background + attack bursts)")
                ],
                format_func=lambda x: x[1]
            )[0]

        with c2:
            count = st.slider("Event Batch Size", min_value=10, max_value=200, value=30, step=5)

        with c3:
            trigger_sim = st.button("🚀 Run Scenario", use_container_width=True, type="primary")

        if trigger_sim:
            with st.spinner("Generating synthetic packets and passing through detection engine..."):
                events = generate_events(scenario, count)
                alerts_count, breakdown = run_pipeline_for_events(events, repository)
                
                if alerts_count > 0:
                    st.success(f"Generated {len(events)} events. Triggered **{alerts_count} real security alert(s)**!")
                    for rname, cnt in breakdown.items():
                        st.markdown(f"- **{rname}**: {cnt} alert(s)")
                else:
                    st.info(f"Generated {len(events)} normal events. 0 security alerts triggered (Normal baseline).")

    # -------------------------------------------------------------
    # TAB 2: REAL SCAPY PACKET CAPTURE
    # -------------------------------------------------------------
    with tab_live:
        st.warning("⚠️ **Administrative Privileges Required**: Live packet capture requires Administrator rights on Windows (with Npcap installed in WinPcap API-compatible Mode) or root privileges on Linux.")

        col_iface, col_dur, col_cnt = st.columns(3)
        with col_iface:
            iface = st.text_input("Capture Interface", value="eth0", help="e.g. Ethernet, Wi-Fi, eth0, or loopback")
        with col_dur:
            duration = st.number_input("Timeout (seconds)", min_value=5, max_value=120, value=15)
        with col_cnt:
            max_pkts = st.number_input("Max Packets", min_value=10, max_value=1000, value=50)

        c_start, c_stop = st.columns(2)
        with c_start:
            start_sniff = st.button("▶️ Start Live Sniffing", use_container_width=True)
        with c_stop:
            stop_sniff = st.button("⏹️ Stop Sniffing", use_container_width=True)

        if start_sniff:
            st.info(f"Initiating live capture on interface `{iface}` for {duration} seconds (or {max_pkts} packets)...")
            try:
                engine = DetectionEngine()
                alert_mgr = AlertManager(repository)
                captured_count = 0

                def packet_handler(pkt):
                    nonlocal captured_count
                    ev = parse_packet(pkt)
                    if ev:
                        repository.insert_event(ev)
                        alerts = engine.process(ev)
                        for a in alerts:
                            alert_mgr.process_alert(a)
                        captured_count += 1

                cap = PacketCapture(
                    interface=iface,
                    count=int(max_pkts),
                    duration=int(duration),
                    callback=packet_handler
                )
                cap.start()
                with st.spinner(f"Sniffing packets on {iface}..."):
                    time.sleep(min(duration, 5))
                cap.stop()

                if captured_count > 0:
                    st.success(f"Live capture complete! Processed {captured_count} packets through the detection engine.")
                else:
                    st.warning("No packets captured. Check if interface name is valid or if Npcap is installed.")
            except PermissionError:
                st.error("Permission denied: Please restart your terminal/IDE as Administrator to enable live Scapy packet sniffing.")
            except Exception as e:
                st.error(f"Live capture error: {e}. Note: You can always use the 'Safe Demo Attack Simulator' tab without special privileges.")

    st.markdown("---")

    # -------------------------------------------------------------
    # LIVE FEED: RECENT EVENTS & ALERTS (Dynamic 3s auto-refresh)
    # -------------------------------------------------------------
    @st.fragment(run_every=3)
    def render_live_stream_tables():
        now_str = datetime.now().strftime("%H:%M:%S")
        st.markdown(
            f"<div style='display: flex; justify-content: space-between; align-items: center; background: #0b0f17; padding: 4px 10px; border-radius: 6px; border: 1px solid #1a2233; margin-bottom: 10px; font-size: 11px; font-family: monospace;'>"
            f"<div><span style='color: #00ff9d;'>● LIVE TELEMETRY STREAM</span> &nbsp; (Auto-polling every 3s)</div>"
            f"<div style='color: #94a3b8;'>Updated: <b>{now_str}</b></div>"
            f"</div>",
            unsafe_allow_html=True
        )
        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>📡 RECENT NETWORK EVENTS (SQLITE)</p>", unsafe_allow_html=True)
            events = repository.get_recent_events(limit=15)
            if events:
                df_ev = pd.DataFrame(events)
                cols = [c for c in ['timestamp', 'source_ip', 'destination_ip', 'destination_port', 'protocol', 'tcp_flags'] if c in df_ev.columns]
                st.dataframe(df_ev[cols], use_container_width=True, height=280)
            else:
                st.caption("No network events recorded.")

        with c_right:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>🚨 RECENT INTRUSION ALERTS (SQLITE)</p>", unsafe_allow_html=True)
            alerts = repository.get_recent_alerts(limit=15)
            if alerts:
                df_al = pd.DataFrame(alerts)
                cols = [c for c in ['severity', 'rule_name', 'source_ip', 'status', 'occurrence_count', 'timestamp'] if c in df_al.columns]
                st.dataframe(df_al[cols], use_container_width=True, height=280)
            else:
                st.caption("No alerts triggered.")

    render_live_stream_tables()
