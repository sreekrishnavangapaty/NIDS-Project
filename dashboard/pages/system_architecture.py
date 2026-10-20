"""System Architecture page illustrating the NIDS pipeline."""
import streamlit as st


def render_system_architecture():
    st.markdown("### 🏗️ System Architecture & Data Pipeline")
    st.caption("End-to-end telemetry flow from raw packet ingestion to forensic SOC dashboard display.")

    pipeline_diagram = """
┌────────────────────────────────────────────────────────┐
│         [1] Network Traffic / Safe Demo Generator      │
└───────────────────────────┬────────────────────────────┘
                            │ Raw Layer 2/3 Frames
                            ▼
┌────────────────────────────────────────────────────────┐
│         [2] Scapy Ingestion Engine (promiscuous / raw) │
└───────────────────────────┬────────────────────────────┘
                            │ Raw Packets (TCP/UDP/ICMP)
                            ▼
┌────────────────────────────────────────────────────────┐
│         [3] Protocol Packet Parser (header decode)     │
└───────────────────────────┬────────────────────────────┘
                            │ Normalized NetworkEvents
                            ▼
┌────────────────────────────────────────────────────────┐
│         [4] Feature Extraction Layer (SYN/ports/counts)│
└───────────────────────────┬────────────────────────────┘
                            │ Extracted & Window Features
                            ▼
┌────────────────────────────────────────────────────────┐
│         [5] Detection Engine & Rules (RULE 001 - 003)  │
└───────────────────────────┬────────────────────────────┘
                            │ Threat Detection Triggers
                            ▼
┌────────────────────────────────────────────────────────┐
│         [6] Alert Manager (Deduplication & Forensics)  │
└───────────────────────────┬────────────────────────────┘
                            │ Verified Alert Records
                            ▼
┌────────────────────────────────────────────────────────┐
│         [7] SQLite Persistent DB (Indexed + WAL Mode)  │
└───────────────────────────┬────────────────────────────┘
                            │ SQL Queries & Aggregations
                            ▼
┌────────────────────────────────────────────────────────┐
│         [8] Analytics Engine (Matplotlib Visualizations│
└───────────────────────────┬────────────────────────────┘
                            │ Live Streamlit & API Data
                            ▼
┌────────────────────────────────────────────────────────┐
│         [9] Streamlit SOC Console & FastAPI REST API   │
└────────────────────────────────────────────────────────┘
"""
    st.code(pipeline_diagram.strip(), language="text")

    st.markdown("---")
    st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 12px 0;'>COMPONENT SPECIFICATIONS & IMPLEMENTATION STATUS</p>", unsafe_allow_html=True)

    components = [
        {
            "stage": "1. Packet Source",
            "tech": "Local NIC / Synthetic Attack Generator",
            "desc": "Supports live Ethernet/Wi-Fi promiscuous interfaces or controlled reproducible attack scenarios (Port Scan, Repeated Connections, High Rate) on authorized targets."
        },
        {
            "stage": "2. Scapy Capture",
            "tech": "scapy.all.sniff / Raw Sockets",
            "desc": "Non-blocking background packet sniffing using threading. Captures layer 2/3 frames with configurable packet count and timeout limits."
        },
        {
            "stage": "3. Packet Parser",
            "tech": "app.capture.packet_parser",
            "desc": "Safely dissects raw IP/TCP/UDP/ICMP frames. Handles malformed or non-IP packets without crashing. Maps TCP control flags (SYN, ACK, RST, FIN)."
        },
        {
            "stage": "4. Feature Extraction",
            "tech": "app.features.extractor",
            "desc": "Transforms raw events into analytical features: unique destination ports contacted, SYN packet ratios, connection frequency, and protocol breakdowns."
        },
        {
            "stage": "5. Detection Engine",
            "tech": "app.detection.engine + rules",
            "desc": "Sliding-window correlation engine evaluating traffic against Port Scan (RULE-001), Repeated Connections (RULE-002), and High Connection Rate (RULE-003)."
        },
        {
            "stage": "6. Alert Manager",
            "tech": "app.alerts.alert_manager",
            "desc": "Handles alert lifecycle: assigns unique IDs, synthesizes JSON forensic evidence, deduplicates repeated alerts within sliding windows, and tracks occurrence counts."
        },
        {
            "stage": "7. SQLite Storage",
            "tech": "SQLite 3 with Write-Ahead Logging (WAL)",
            "desc": "Persistent indexed relational database (network_events, alerts) replacing deprecated flat CSV logs. Supports sub-millisecond querying and transactions."
        },
        {
            "stage": "8. Analytics Engine",
            "tech": "app.analytics.statistics + Matplotlib",
            "desc": "Performs aggregate threat statistics and generates clean dark-themed SOC charts (timeline, protocol pie, port bars) using pure Matplotlib (no Plotly)."
        },
        {
            "stage": "9. Presentation Layer",
            "tech": "Streamlit + FastAPI REST API",
            "desc": "Dual interface: Streamlit Command Center for human analysts (8 full pages) and FastAPI REST endpoints for SIEM integration (/alerts, /traffic, /statistics)."
        }
    ]

    for comp in components:
        with st.container():
            c1, c2 = st.columns([1, 3])
            with c1:
                st.markdown(f"**{comp['stage']}**")
                st.caption(f"`{comp['tech']}`")
            with c2:
                st.markdown(comp['desc'])
            st.divider()
