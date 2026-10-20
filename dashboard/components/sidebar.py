import streamlit as st

def render_sidebar(db_available=True):
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 10px 0;">
            <h2 style="color: #00d4ff; margin: 0; font-family: monospace; letter-spacing: 2px;">🛡️ NIDS SOC</h2>
            <p style="color: #888888; font-size: 11px; margin: 4px 0 0 0; text-transform: uppercase;">Intrusion Detection System</p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")

        mode = st.session_state.get('mode', 'DEMO')
        col1, col2 = st.columns(2)
        with col1:
            st.caption("MODE")
            st.markdown(f"**`{mode}`**")
        with col2:
            st.caption("STATUS")
            if db_available:
                st.markdown("<span style='color: #00ff9d; font-weight: bold;'>● Online</span>", unsafe_allow_html=True)
            else:
                st.markdown("<span style='color: #ff0040; font-weight: bold;'>● Offline</span>", unsafe_allow_html=True)

        st.markdown("---")
        pages = [
            "Overview",
            "Live Monitoring",
            "Security Alerts",
            "Alert Investigation",
            "Traffic Analysis",
            "Detection Rules",
            "System Architecture",
            "Settings"
        ]
        
        # Support deep-link selection from alerts page
        default_index = 0
        if "navigate_to" in st.session_state and st.session_state["navigate_to"] in pages:
            default_index = pages.index(st.session_state["navigate_to"])
            del st.session_state["navigate_to"]
            
        page = st.radio("SOC NAVIGATION", pages, index=default_index)

        st.markdown("---")
        st.caption("SYSTEM TELEMETRY")
        st.caption("Database: SQLite (WAL mode)")
        st.caption("Capture Engine: Scapy 2.8.0")
        st.caption("Backend: FastAPI + Streamlit")
        return page
