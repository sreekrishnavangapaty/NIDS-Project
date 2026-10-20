"""Security Alerts page for NIDS Command Center."""
import streamlit as st
import pandas as pd
from dashboard.components.metrics import render_severity_badge, render_status_badge


def render_security_alerts(repository):
    st.markdown("### 🚨 Security Alerts Console")
    st.caption("Inspect, filter, and triage real-time intrusion alerts stored in SQLite.")

    # 1. Filters Section
    with st.expander("🔍 Filter Alerts", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            severity_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with col2:
            status_filter = st.multiselect("Status", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
        with col3:
            rule_filter = st.selectbox("Detection Rule", ["ALL", "PORT_SCAN", "REPEATED_CONNECTION", "HIGH_RATE"])
        with col4:
            ip_query = st.text_input("Source IP", placeholder="e.g. 10.0.0.50")

    # 2. Query Alerts from SQLite
    rule_arg = None if rule_filter == "ALL" else rule_filter
    alerts = repository.get_alerts(limit=500, rule_name=rule_arg)
    df = pd.DataFrame(alerts)

    if not df.empty:
        # Apply dataframe filters
        if severity_filter:
            df = df[df['severity'].str.upper().isin(severity_filter)]
        if status_filter:
            df = df[df['status'].str.upper().isin(status_filter)]
        if ip_query:
            df = df[df['source_ip'].str.contains(ip_query, na=False)]

        st.markdown(f"<p style='font-size: 13px; color: #94a3b8; margin: 4px 0 10px 0;'>Showing <b>{len(df)}</b> alert record(s) matching current criteria.</p>", unsafe_allow_html=True)

        # Required columns: severity, rule, source IP, destination IP, first seen, last seen, occurrence count, status
        req_columns = ['id', 'severity', 'rule_name', 'source_ip', 'destination_ip', 'first_seen', 'last_seen', 'occurrence_count', 'status']
        display_cols = [c for c in req_columns if c in df.columns]
        
        # Display alerts table
        st.dataframe(df[display_cols], use_container_width=True, height=320)

        # 3. Export Section (Requirement 25)
        st.markdown("---")
        c_exp1, c_exp2 = st.columns(2)
        with c_exp1:
            csv_alerts = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Export Filtered Alerts (CSV)",
                data=csv_alerts,
                file_name="nids_security_alerts.csv",
                mime="text/csv",
                use_container_width=True
            )
        with c_exp2:
            all_alerts_raw = repository.export_alerts_csv()
            all_alerts_df = pd.DataFrame(all_alerts_raw)
            if not all_alerts_df.empty:
                full_csv = all_alerts_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📦 Export Entire Alert Database (CSV)",
                    data=full_csv,
                    file_name="nids_all_alerts.csv",
                    mime="text/csv",
                    use_container_width=True
                )

        # Quick Jump to Alert Investigation
        st.markdown("---")
        st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin: 0 0 6px 0;'>🔎 DIRECT INVESTIGATION DISPATCH</p>", unsafe_allow_html=True)
        c_sel, c_act = st.columns([3, 1], vertical_alignment="bottom")
        with c_sel:
            selected_aid = st.selectbox(
                "Select Alert to Investigate",
                df['id'].tolist(),
                format_func=lambda x: f"Alert #{x} — {df[df['id']==x]['rule_name'].values[0]} ({df[df['id']==x]['source_ip'].values[0]})"
            )
        with c_act:
            if st.button("Open in Forensics", type="primary", use_container_width=True):
                st.session_state['selected_alert_id'] = selected_aid
                st.session_state['navigate_to'] = "Alert Investigation"
                st.rerun()

    else:
        st.info("No security alerts found matching the specified filters.")
