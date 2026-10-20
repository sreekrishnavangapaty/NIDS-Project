"""Overview page for NIDS Command Center with real-time dynamic auto-refresh."""
import streamlit as st
import pandas as pd
from datetime import datetime
from dashboard.components.metrics import render_metric_row
from dashboard.components.charts import (
    plot_alerts_over_time,
    plot_alerts_by_severity,
    plot_protocol_distribution,
    plot_top_source_ips
)


def render_overview(repository):
    # Header with Live Stream Toolbar
    col_hdr, col_ctrl = st.columns([3, 1], vertical_alignment="center")
    with col_hdr:
        st.markdown("### 🛡️ Security Overview & Threat Intelligence")
        st.caption("Live network security posture and intrusion telemetry backed by SQLite persistent storage.")
    with col_ctrl:
        refresh_choice = st.selectbox(
            "Live Stream",
            options=[3, 2, 5, 0],
            format_func=lambda x: f"🟢 Live (Every {x}s)" if x > 0 else "⏸️ Paused (Manual)",
            index=0,
            key="overview_refresh_choice",
            help="Configures background live data polling interval."
        )

    run_interval = refresh_choice if refresh_choice > 0 else None

    # Dynamic Live Fragment: Auto-refreshes every 2 to 5 seconds
    @st.fragment(run_every=run_interval)
    def render_live_overview_content():
        # 1. Fetch real statistics from SQLite on each tick
        stats = repository.get_statistics()

        # Live status timestamp bar
        now_str = datetime.now().strftime("%H:%M:%S")
        status_text = f"<span style='color: #00ff9d;'>● LIVE TELEMETRY</span> &nbsp; Updated: <b>{now_str}</b>" if run_interval else f"<span style='color: #94a3b8;'>⏸ PAUSED</span> &nbsp; Snapshot: <b>{now_str}</b>"
        st.markdown(
            f"<div style='display: flex; justify-content: space-between; align-items: center; background: #0b0f17; padding: 6px 12px; border-radius: 6px; border: 1px solid #1a2233; margin-bottom: 12px; font-size: 12px; font-family: monospace;'>"
            f"<div>{status_text}</div>"
            f"<div style='color: #94a3b8;'>SQLite State: <b>{stats.get('total_events', 0):,}</b> events | <b>{stats.get('total_alerts', 0):,}</b> alerts</div>"
            f"</div>",
            unsafe_allow_html=True
        )

        # Metric Row 1: Volume & Threat Severity
        row1_metrics = [
            {'label': 'Total Events', 'value': f"{stats.get('total_events', 0):,}", 'color': '#00d4ff', 'icon': '📊'},
            {'label': 'Total Alerts', 'value': f"{stats.get('total_alerts', 0):,}", 'color': '#ffd000', 'icon': '🚨'},
            {'label': 'Critical Alerts', 'value': f"{stats.get('critical_alerts', 0):,}", 'color': '#ff0040', 'icon': '🔥'},
            {'label': 'High Alerts', 'value': f"{stats.get('high_alerts', 0):,}", 'color': '#ff6b00', 'icon': '⚠️'},
        ]
        render_metric_row(row1_metrics)

        # Metric Row 2: Detection-specific & Host Telemetry
        row2_metrics = [
            {'label': 'Port Scan Alerts', 'value': f"{stats.get('port_scan_alerts', 0):,}", 'color': '#ff6b00', 'icon': '🎯'},
            {'label': 'Repeated Conn Alerts', 'value': f"{stats.get('repeated_conn_alerts', 0):,}", 'color': '#ffd000', 'icon': '🔄'},
            {'label': 'Unique Source IPs', 'value': f"{stats.get('unique_source_ips', 0):,}", 'color': '#00ff9d', 'icon': '🌐'},
            {'label': 'Unique Dest IPs', 'value': f"{stats.get('unique_dest_ips', 0):,}", 'color': '#a855f7', 'icon': '🖥️'},
        ]
        render_metric_row(row2_metrics)

        st.markdown("---")

        # 2. Charts Section with Symmetrical Row-by-Row Columns
        alerts_data = repository.get_recent_alerts(500)
        events_data = repository.get_recent_events(500)

        alerts_df = pd.DataFrame(alerts_data)
        events_df = pd.DataFrame(events_data)

        # Chart Row 1
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>📈 ALERTS OVER TIME</p>", unsafe_allow_html=True)
            st.pyplot(plot_alerts_over_time(alerts_df), use_container_width=True)
        with c2:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>🌐 PROTOCOL DISTRIBUTION</p>", unsafe_allow_html=True)
            st.pyplot(plot_protocol_distribution(events_df), use_container_width=True)

        st.write("")

        # Chart Row 2
        c3, c4 = st.columns(2)
        with c3:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>🚨 SEVERITY BREAKDOWN</p>", unsafe_allow_html=True)
            st.pyplot(plot_alerts_by_severity(alerts_df), use_container_width=True)
        with c4:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 2px;'>💻 TOP ACTIVE SOURCE IPS</p>", unsafe_allow_html=True)
            st.pyplot(plot_top_source_ips(events_df), use_container_width=True)

        st.markdown("---")

        # 3. Recent Alerts Table
        st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 8px 0;'>🚨 RECENT INTRUSION ALERTS (SQLITE LOG)</p>", unsafe_allow_html=True)
        if not alerts_df.empty:
            display_cols = [c for c in ['id', 'severity', 'rule_name', 'source_ip', 'destination_ip', 'status', 'occurrence_count', 'timestamp'] if c in alerts_df.columns]
            st.dataframe(alerts_df[display_cols].head(8), use_container_width=True, height=220)
        else:
            st.info("No security alerts logged yet. Run Demo Mode or Live Monitoring to generate network events.")

    # Call the live fragment
    render_live_overview_content()
