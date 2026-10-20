import streamlit as st
import pandas as pd

def render_alerts_table(alerts_df: pd.DataFrame):
    if alerts_df is None or alerts_df.empty:
        st.info("No alerts found matching criteria.")
        return
    st.dataframe(alerts_df, use_container_width=True)

def render_events_table(events_df: pd.DataFrame):
    if events_df is None or events_df.empty:
        st.info("No events found matching criteria.")
        return
    st.dataframe(events_df, use_container_width=True)

def render_rules_table(rules: list[dict]):
    if not rules:
        st.info("No detection rules configured.")
        return
    df = pd.DataFrame(rules)
    st.dataframe(df, use_container_width=True)
