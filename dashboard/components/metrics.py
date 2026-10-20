import streamlit as st

def render_metric_card(label, value, delta=None, color='#00d4ff', icon='●'):
    st.markdown(f"""
    <div class="metric-card" style="border-top-color: {color};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
            <span class="metric-label">{label}</span>
            <span style="color: {color}; font-size: 10px; opacity: 0.85;">{icon}</span>
        </div>
        <div class="metric-value">{value}</div>
    </div>
    """, unsafe_allow_html=True)


def render_metric_row(metrics: list[dict]):
    cols = st.columns(len(metrics))
    for i, col in enumerate(cols):
        with col:
            m = metrics[i]
            render_metric_card(
                m['label'],
                m['value'],
                color=m.get('color', '#00d4ff'),
                icon=m.get('icon', '●')
            )


def render_severity_badge(severity):
    colors = {
        "CRITICAL": {"bg": "rgba(255, 0, 64, 0.15)", "text": "#ff3366", "border": "#ff0040"},
        "HIGH": {"bg": "rgba(255, 107, 0, 0.15)", "text": "#ff8533", "border": "#ff6b00"},
        "MEDIUM": {"bg": "rgba(255, 208, 0, 0.15)", "text": "#ffd533", "border": "#ffd000"},
        "LOW": {"bg": "rgba(0, 212, 255, 0.15)", "text": "#33ddff", "border": "#00d4ff"}
    }
    s = str(severity).upper()
    style = colors.get(s, {"bg": "rgba(255,255,255,0.1)", "text": "#e0e0e0", "border": "#666666"})
    return f'<span style="background-color:{style["bg"]}; color:{style["text"]}; border:1px solid {style["border"]}; padding:3px 8px; border-radius:4px; font-weight:600; font-size:11px; letter-spacing:0.5px; font-family: monospace;">{s}</span>'


def render_status_badge(status):
    colors = {
        "NEW": {"bg": "rgba(255, 0, 64, 0.15)", "text": "#ff3366", "border": "#ff0040"},
        "INVESTIGATING": {"bg": "rgba(255, 208, 0, 0.15)", "text": "#ffd533", "border": "#ffd000"},
        "RESOLVED": {"bg": "rgba(0, 255, 157, 0.15)", "text": "#33ffb5", "border": "#00ff9d"},
        "FALSE_POSITIVE": {"bg": "rgba(148, 163, 184, 0.15)", "text": "#94a3b8", "border": "#64748b"}
    }
    s = str(status).upper()
    style = colors.get(s, {"bg": "rgba(255,255,255,0.1)", "text": "#e0e0e0", "border": "#666666"})
    return f'<span style="background-color:{style["bg"]}; color:{style["text"]}; border:1px solid {style["border"]}; padding:3px 8px; border-radius:4px; font-weight:600; font-size:11px; letter-spacing:0.5px; font-family: monospace;">{s}</span>'
