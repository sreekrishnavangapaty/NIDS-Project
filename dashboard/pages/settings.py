"""Settings and configuration management page."""
import streamlit as st
from app.config import config
from app.detection import thresholds
from app.database.repository import DatabaseRepository


def render_settings(cfg=None):
    st.markdown("### ⚙️ System Configuration & Threshold Settings")
    st.caption("Centralized configuration for detection rule sensitivity, correlation windows, and storage management.")

    repo = DatabaseRepository()

    # SECTION 1: DETECTION THRESHOLDS
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 16px 0 6px 0;'>🎯 DETECTION SENSITIVITY & TIME CORRELATION</p>", unsafe_allow_html=True)
    st.info("Adjust the sensitivity of detection rules. Changes apply immediately to ongoing detection and sliding-window correlation.")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 0;'>COUNT THRESHOLDS</p>", unsafe_allow_html=True)
        port_scan_thresh = st.number_input(
            "Port Scan: Unique Ports Threshold",
            min_value=3, max_value=100,
            value=int(config.PORT_SCAN_THRESHOLD),
            help="Number of distinct destination ports from one source required to trigger RULE-001"
        )
        rep_conn_thresh = st.number_input(
            "Repeated Connections: Hit Count Threshold",
            min_value=3, max_value=200,
            value=int(config.REPEATED_CONNECTION_THRESHOLD),
            help="Number of connections to the same port required to trigger RULE-002"
        )
        high_rate_thresh = st.number_input(
            "High Connection Rate: Total Connections Threshold",
            min_value=10, max_value=1000,
            value=int(config.HIGH_RATE_THRESHOLD),
            help="Total outbound connections required to trigger RULE-003"
        )

    with col2:
        st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin: 0 0 6px 0;'>CORRELATION WINDOWS (SECONDS)</p>", unsafe_allow_html=True)
        port_scan_win = st.number_input(
            "Port Scan Window (seconds)",
            min_value=2, max_value=300,
            value=int(config.PORT_SCAN_WINDOW),
            help="Time window in seconds to correlate port scan packets"
        )
        rep_conn_win = st.number_input(
            "Repeated Connections Window (seconds)",
            min_value=5, max_value=600,
            value=int(config.REPEATED_CONNECTION_WINDOW),
            help="Time window in seconds to correlate repeated connection attempts"
        )
        high_rate_win = st.number_input(
            "High Connection Rate Window (seconds)",
            min_value=2, max_value=120,
            value=int(config.HIGH_RATE_WINDOW),
            help="Time window in seconds to calculate connection rate"
        )

    if st.button("💾 Apply Threshold Changes", type="primary"):
        config.PORT_SCAN_THRESHOLD = port_scan_thresh
        config.PORT_SCAN_WINDOW = port_scan_win
        config.REPEATED_CONNECTION_THRESHOLD = rep_conn_thresh
        config.REPEATED_CONNECTION_WINDOW = rep_conn_win
        config.HIGH_RATE_THRESHOLD = high_rate_thresh
        config.HIGH_RATE_WINDOW = high_rate_win
        st.success("New thresholds applied successfully to the running system!")

    st.markdown("---")

    # SECTION 2: SYSTEM ENVIRONMENT
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 8px 0;'>🖥️ STORAGE & ENVIRONMENT PARAMETERS</p>", unsafe_allow_html=True)
    c_env1, c_env2 = st.columns(2)
    with c_env1:
        st.text_input("SQLite Database Location", value=config.DATABASE_PATH, disabled=True)
        st.text_input("Alert Deduplication Window", value=f"{config.ALERT_DEDUP_WINDOW} seconds", disabled=True)
    with c_env2:
        st.text_input("Default Sniffer Interface", value=config.CAPTURE_INTERFACE, disabled=True)
        st.text_input("Logging Level", value=config.LOG_LEVEL, disabled=True)

    st.markdown("---")

    # SECTION 3: DATABASE MAINTENANCE
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 6px 0;'>🧹 DATABASE MAINTENANCE & PURGE</p>", unsafe_allow_html=True)
    st.caption("Clear captured event logs and alerts to start a fresh monitoring session.")
    
    total_ev = repo.get_event_count()
    total_al = repo.get_alert_count()
    st.markdown(f"**Current SQLite Records:** `{total_ev:,}` events | `{total_al:,}` security alerts")

    c_del1, c_del2 = st.columns([1, 2], vertical_alignment="center")
    with c_del1:
        if st.button("🗑️ Clear All Database Records", type="secondary", use_container_width=True):
            repo.clear_all_data()
            st.warning("Database cleared. All events and alerts purged.")
            st.rerun()
    with c_del2:
        st.caption("Permanently purges all records from `network_events` and `alerts` tables in SQLite.")
