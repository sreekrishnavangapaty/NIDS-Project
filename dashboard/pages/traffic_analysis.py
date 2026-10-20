"""Traffic Analysis page with all 8 required Matplotlib visualizations in symmetrical grid alignment.

Features real-time dynamic auto-refresh every 2 to 5 seconds.
"""
import streamlit as st
import pandas as pd
from datetime import datetime
from dashboard.components.charts import (
    plot_events_over_time,
    plot_alerts_over_time,
    plot_alerts_by_severity,
    plot_protocol_distribution,
    plot_top_source_ips,
    plot_top_destination_ports,
    plot_detection_rule_distribution,
    plot_unique_dest_ports_per_source
)


def render_traffic_analysis(repository):
    # Header with Live Auto-Refresh Toolbar
    col_hdr, col_ctrl = st.columns([3, 1], vertical_alignment="center")
    with col_hdr:
        st.markdown("### 📊 Network Traffic & Threat Telemetry")
        st.caption("Live threat intelligence generated exclusively with Matplotlib from real SQLite database records.")
    with col_ctrl:
        refresh_choice = st.selectbox(
            "Telemetry Stream",
            options=[3, 2, 5, 0],
            format_func=lambda x: f"🟢 Live (Every {x}s)" if x > 0 else "⏸️ Paused (Manual)",
            index=0,
            help="Configures background live data polling interval."
        )

    run_interval = refresh_choice if refresh_choice > 0 else None

    # Filter Controls (outside fragment to preserve filter state smoothly)
    with st.expander("🔍 Filter Telemetry", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            proto_filter = st.selectbox("Protocol Filter", ["ALL", "TCP", "UDP", "ICMP"])
        with c2:
            ip_filter = st.text_input("Source IP Filter", placeholder="e.g. 192.168.1.")

    # Dynamic Live Fragment: Auto-refreshes every 2 to 5 seconds based on user choice
    @st.fragment(run_every=run_interval)
    def render_live_charts():
        # 1. Fetch latest data from SQLite on each tick
        events = repository.get_events(limit=2000)
        alerts = repository.get_alerts(limit=1000)

        events_df = pd.DataFrame(events)
        alerts_df = pd.DataFrame(alerts)

        if not events_df.empty:
            if proto_filter != "ALL":
                events_df = events_df[events_df['protocol'] == proto_filter]
            if ip_filter:
                events_df = events_df[events_df['source_ip'].str.contains(ip_filter, na=False)]

        # Live status timestamp bar
        now_str = datetime.now().strftime("%H:%M:%S")
        status_text = f"<span style='color: #00ff9d;'>● LIVE</span> &nbsp; Last updated: <b>{now_str}</b>" if run_interval else f"<span style='color: #94a3b8;'>⏸ PAUSED</span> &nbsp; Snapshot: <b>{now_str}</b>"
        st.markdown(
            f"<div style='display: flex; justify-content: space-between; align-items: center; background: #0b0f17; padding: 6px 12px; border-radius: 6px; border: 1px solid #1a2233; margin-bottom: 12px; font-size: 12px; font-family: monospace;'>"
            f"<div>{status_text}</div>"
            f"<div style='color: #94a3b8;'>DB Records: <b>{len(events_df):,}</b> events | <b>{len(alerts_df):,}</b> alerts</div>"
            f"</div>",
            unsafe_allow_html=True
        )

        # 2. Symmetrical 2x2 rows
        # Row 1: Temporal Trends
        c_time1, c_time2 = st.columns(2)
        with c_time1:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>1. NETWORK EVENTS OVER TIME</p>", unsafe_allow_html=True)
            st.pyplot(plot_events_over_time(events_df), use_container_width=True)
        with c_time2:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>2. SECURITY ALERTS OVER TIME</p>", unsafe_allow_html=True)
            st.pyplot(plot_alerts_over_time(alerts_df), use_container_width=True)

        st.write("")

        # Row 2: Threat & Rule Distributions
        c_sev1, c_sev2 = st.columns(2)
        with c_sev1:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>3. ALERTS BY SEVERITY</p>", unsafe_allow_html=True)
            st.pyplot(plot_alerts_by_severity(alerts_df), use_container_width=True)
        with c_sev2:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>7. DETECTION RULE DISTRIBUTION</p>", unsafe_allow_html=True)
            st.pyplot(plot_detection_rule_distribution(alerts_df), use_container_width=True)

        st.write("")

        # Row 3: Protocol & Volume
        c_net1, c_net2 = st.columns(2)
        with c_net1:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>4. PROTOCOL BREAKDOWN</p>", unsafe_allow_html=True)
            st.pyplot(plot_protocol_distribution(events_df), use_container_width=True)
        with c_net2:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>5. TOP SOURCE IPS BY VOLUME</p>", unsafe_allow_html=True)
            st.pyplot(plot_top_source_ips(events_df), use_container_width=True)

        st.write("")

        # Row 4: Targeted Ports & Scan Indicators
        c_net3, c_net4 = st.columns(2)
        with c_net3:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>6. TOP TARGETED DESTINATION PORTS</p>", unsafe_allow_html=True)
            st.pyplot(plot_top_destination_ports(events_df), use_container_width=True)
        with c_net4:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>8. UNIQUE PORTS PER SOURCE (PORT SCAN INDICATOR)</p>", unsafe_allow_html=True)
            st.pyplot(plot_unique_dest_ports_per_source(events_df), use_container_width=True)

        st.markdown("---")

        # 3. Raw Traffic Table and CSV Export
        c_tbl, c_exp = st.columns([3, 1], vertical_alignment="center")
        with c_tbl:
            st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0;'>💾 RAW NETWORK TRAFFIC EVENT LOGS</p>", unsafe_allow_html=True)
            st.caption(f"Displaying up to 200 most recent captured network events.")
        with c_exp:
            if not events_df.empty:
                csv_data = events_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📥 Download Events CSV",
                    data=csv_data,
                    file_name="nids_network_events.csv",
                    mime="text/csv",
                    use_container_width=True
                )

        if not events_df.empty:
            cols_to_show = [c for c in ['id', 'timestamp', 'source_ip', 'destination_ip', 'destination_port', 'protocol', 'tcp_flags', 'packet_size'] if c in events_df.columns]
            st.dataframe(events_df[cols_to_show].head(200), use_container_width=True, height=260)
        else:
            st.info("No raw network events found in database.")

    # Call the live fragment
    render_live_charts()
