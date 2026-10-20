import streamlit as st
import sys
import os

# Set page config - must be first
st.set_page_config(
    page_title='NIDS SOC Command Center',
    layout='wide',
    page_icon='🛡️',
    initial_sidebar_state='expanded'
)

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dashboard.components.sidebar import render_sidebar
from dashboard.pages.overview import render_overview
from dashboard.pages.live_monitoring import render_live_monitoring
from dashboard.pages.security_alerts import render_security_alerts
from dashboard.pages.alert_investigation import render_alert_investigation
from dashboard.pages.traffic_analysis import render_traffic_analysis
from dashboard.pages.detection_rules import render_detection_rules
from dashboard.pages.system_architecture import render_system_architecture
from dashboard.pages.settings import render_settings

# Database and App Configuration
try:
    from app.database.connection import init_db
    from app.database.repository import DatabaseRepository
    from app.config import config
    db_available = True
except Exception:
    db_available = False
    repo = None


def apply_theme():
    st.markdown("""
    <style>
    /* Global Background & Typography */
    .stApp {
        background-color: #090c13 !important;
        color: #e2e8f0 !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    }

    /* Container Spacing & Alignment */
    .block-container {
        padding-top: 1.8rem !important;
        padding-bottom: 2.5rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        max-width: 100% !important;
    }

    /* Top Bar & Header Alignment */
    h1, h2, h3, h4, h5, h6 {
        color: #f8fafc !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em !important;
    }

    /* CRITICAL FIX: Matplotlib charts size constraint.
       Prevents charts from ballooning/expanding when window is minimized or resized */
    [data-testid="stPlot"],
    [data-testid="stImage"],
    .stPlot,
    .stImage {
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        background: #0f1420 !important;
        border: 1px solid #1e2638 !important;
        border-radius: 8px !important;
        padding: 6px !important;
        margin-bottom: 8px !important;
        max-height: 245px !important;
        overflow: hidden !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }

    [data-testid="stPlot"]:hover,
    [data-testid="stImage"]:hover {
        border-color: #00d4ff55 !important;
        box-shadow: 0 4px 16px rgba(0, 212, 255, 0.07) !important;
    }

    [data-testid="stPlot"] img,
    [data-testid="stImage"] img,
    .stPlot img,
    .stImage img {
        max-height: 230px !important;
        max-width: 520px !important;
        width: 100% !important;
        height: auto !important;
        object-fit: contain !important;
        margin: 0 auto !important;
        display: block !important;
    }

    /* Sleek SOC Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, #101522 0%, #0d121c 100%) !important;
        border: 1px solid #1e2638 !important;
        border-top: 3px solid #00d4ff !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        min-height: 84px !important;
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25) !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
        margin-bottom: 6px !important;
    }

    .metric-card:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 14px rgba(0, 0, 0, 0.35) !important;
    }

    .metric-label {
        margin: 0 0 4px 0 !important;
        padding: 0 !important;
        color: #94a3b8 !important;
        font-size: 11px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.08em !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
    }

    .metric-value {
        margin: 0 !important;
        padding: 0 !important;
        color: #f8fafc !important;
        font-size: 24px !important;
        font-weight: 700 !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace !important;
        line-height: 1.1 !important;
    }

    /* Form controls, inputs, selects */
    div[data-baseweb="select"] > div,
    input, textarea {
        background-color: #0f1420 !important;
        border-color: #1e2638 !important;
        color: #f8fafc !important;
        border-radius: 6px !important;
    }

    /* Buttons */
    button[kind="primary"],
    .stButton > button {
        border-radius: 6px !important;
        font-weight: 600 !important;
        letter-spacing: 0.02em !important;
        transition: all 0.2s ease !important;
    }

    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px !important;
        background-color: transparent !important;
        border-bottom: 1px solid #1e2638 !important;
    }

    .stTabs [data-baseweb="tab"] {
        background-color: transparent !important;
        border: none !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
        padding: 8px 16px !important;
        border-radius: 6px 6px 0 0 !important;
    }

    .stTabs [aria-selected="true"] {
        color: #00d4ff !important;
        border-bottom: 2px solid #00d4ff !important;
    }

    /* Tables & Dataframes */
    [data-testid="stDataFrame"] {
        border: 1px solid #1e2638 !important;
        border-radius: 8px !important;
        overflow: hidden !important;
    }

    /* Horizontal divider */
    hr {
        margin: 1.2rem 0 !important;
        border-color: #1a2233 !important;
    }
    </style>
    """, unsafe_allow_html=True)


def main():
    apply_theme()

    if db_available:
        init_db()
        repo = DatabaseRepository()
    else:
        st.error("Database connection failed. Check SQLite database path.")
        return

    page = render_sidebar(db_available)

    if page == "Overview":
        render_overview(repo)
    elif page == "Live Monitoring":
        render_live_monitoring(repo)
    elif page == "Security Alerts":
        render_security_alerts(repo)
    elif page == "Alert Investigation":
        render_alert_investigation(repo)
    elif page == "Traffic Analysis":
        render_traffic_analysis(repo)
    elif page == "Detection Rules":
        render_detection_rules()
    elif page == "System Architecture":
        render_system_architecture()
    elif page == "Settings":
        render_settings(config)


if __name__ == "__main__":
    main()
