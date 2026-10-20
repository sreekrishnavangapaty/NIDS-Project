"""Matplotlib charts for SOC Traffic Analysis and Security Overview.

Optimized for responsive SOC layouts:
- Prevents ballooning/expanding when window is minimized or resized
- Symmetrical heights and margins for perfect grid alignment
- Dark-themed aesthetic matching SOC command centers
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
from typing import Optional

BG_COLOR = "#0f1420"
PANEL_COLOR = "#121826"
TEXT_COLOR = "#cbd5e1"
MUTED_TEXT = "#64748b"
GRID_COLOR = "#1e293b"
SEVERITY_COLORS = {
    "CRITICAL": "#ff0040",
    "HIGH": "#ff6b00",
    "MEDIUM": "#ffd000",
    "LOW": "#00d4ff"
}

# Standard compact figure size ensuring perfect alignment and responsiveness
DEFAULT_FIGSIZE = (5.6, 2.45)
DEFAULT_DPI = 110


def _setup_fig(figsize=DEFAULT_FIGSIZE):
    fig, ax = plt.subplots(figsize=figsize, dpi=DEFAULT_DPI)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    ax.tick_params(colors=TEXT_COLOR, labelsize=7.5)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.xaxis.label.set_size(8.5)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_size(8.5)
    ax.title.set_color("#f8fafc")
    ax.title.set_size(9.5)
    ax.title.set_weight("bold")
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
        spine.set_linewidth(0.8)
    return fig, ax


def _no_data_fig(title="Chart"):
    fig, ax = _setup_fig()
    ax.text(0.5, 0.5, "No data logged yet", color=MUTED_TEXT,
            ha='center', va='center', fontsize=9, style='italic')
    ax.set_title(title, pad=8)
    ax.set_xticks([])
    ax.set_yticks([])
    plt.tight_layout(pad=0.8)
    return fig


def _col(df: pd.DataFrame, *names) -> Optional[str]:
    for n in names:
        if n in df.columns:
            return n
    return None


# 1. Events over time
def plot_events_over_time(data: pd.DataFrame):
    ts_col = _col(data, 'timestamp')
    if data is None or data.empty or not ts_col:
        return _no_data_fig("Network Events Over Time")
    fig, ax = _setup_fig()
    try:
        s = pd.to_datetime(data[ts_col])
        counts = s.dt.floor('min').value_counts().sort_index()
        if counts.empty:
            return _no_data_fig("Network Events Over Time")
        labels = [t.strftime("%H:%M") for t in counts.index]
        ax.plot(labels, counts.values, color='#00ff9d', marker='o', linewidth=1.8, markersize=3.5)
        ax.fill_between(range(len(labels)), counts.values, color='#00ff9d', alpha=0.12)
        ax.set_title("Network Events Over Time", pad=8)
        ax.set_xlabel("Time (HH:MM)")
        ax.set_ylabel("Events")
        ax.tick_params(axis='x', rotation=30)
        ax.grid(True, color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
        plt.tight_layout(pad=0.8)
    except Exception:
        return _no_data_fig("Network Events Over Time")
    return fig


# 2. Alerts over time
def plot_alerts_over_time(data: pd.DataFrame):
    ts_col = _col(data, 'timestamp')
    if data is None or data.empty or not ts_col:
        return _no_data_fig("Security Alerts Over Time")
    fig, ax = _setup_fig()
    try:
        s = pd.to_datetime(data[ts_col])
        counts = s.dt.floor('min').value_counts().sort_index()
        if counts.empty:
            return _no_data_fig("Security Alerts Over Time")
        labels = [t.strftime("%H:%M") for t in counts.index]
        ax.plot(labels, counts.values, color='#ff0040', marker='s', linewidth=1.8, markersize=4)
        ax.fill_between(range(len(labels)), counts.values, color='#ff0040', alpha=0.12)
        ax.set_title("Security Alerts Over Time", pad=8)
        ax.set_xlabel("Time (HH:MM)")
        ax.set_ylabel("Alerts")
        ax.tick_params(axis='x', rotation=30)
        ax.grid(True, color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
        plt.tight_layout(pad=0.8)
    except Exception:
        return _no_data_fig("Security Alerts Over Time")
    return fig


# 3. Alerts by severity
def plot_alerts_by_severity(data: pd.DataFrame):
    sev_col = _col(data, 'severity')
    if data is None or data.empty or not sev_col:
        return _no_data_fig("Alerts by Severity")
    fig, ax = _setup_fig()
    counts = data[sev_col].astype(str).str.upper().value_counts()
    order = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if s in counts]
    for s in counts.index:
        if s not in order:
            order.append(s)
    ordered_counts = counts.reindex(order).fillna(0)
    colors = [SEVERITY_COLORS.get(s, "#00d4ff") for s in order]
    bars = ax.bar(ordered_counts.index, ordered_counts.values, color=colors, width=0.45)
    for b in bars:
        h = b.get_height()
        ax.annotate(f'{int(h)}',
                    xy=(b.get_x() + b.get_width() / 2, h),
                    xytext=(0, 2), textcoords="offset points",
                    ha='center', va='bottom', color=TEXT_COLOR, fontsize=8, weight='bold')
    ax.set_title("Alerts by Severity", pad=8)
    ax.set_ylabel("Alert Count")
    ax.grid(axis='y', color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
    plt.tight_layout(pad=0.8)
    return fig


# 4. Protocol distribution
def plot_protocol_distribution(data: pd.DataFrame):
    proto_col = _col(data, 'protocol')
    if data is None or data.empty or not proto_col:
        return _no_data_fig("Protocol Distribution")
    counts = data[proto_col].dropna().value_counts()
    if counts.empty:
        return _no_data_fig("Protocol Distribution")
    fig, ax = _setup_fig(figsize=(4.5, 2.45))
    colors = ['#00d4ff', '#ff6b00', '#ffd000', '#00ff9d', '#9b5de5']
    wedges, texts, autotexts = ax.pie(
        counts.values,
        labels=counts.index,
        autopct='%1.1f%%',
        colors=colors[:len(counts)],
        startangle=140,
        textprops={'color': TEXT_COLOR, 'fontsize': 8}
    )
    for at in autotexts:
        at.set_color('#090c13')
        at.set_weight('bold')
        at.set_fontsize(8)
    ax.set_title("Protocol Breakdown", pad=8)
    plt.tight_layout(pad=0.8)
    return fig


# 5. Top source IPs
def plot_top_source_ips(data: pd.DataFrame, limit=7):
    src_col = _col(data, 'source_ip', 'src_ip')
    if data is None or data.empty or not src_col:
        return _no_data_fig("Top Source IPs")
    counts = data[src_col].dropna().value_counts().head(limit).sort_values(ascending=True)
    if counts.empty:
        return _no_data_fig("Top Source IPs")
    fig, ax = _setup_fig()
    ax.barh(counts.index, counts.values, color='#00d4ff', height=0.55)
    for idx, val in enumerate(counts.values):
        ax.text(val + 0.1, idx, f"{int(val)}", va='center', color=TEXT_COLOR, fontsize=7.5)
    ax.set_title(f"Top {limit} Source IPs", pad=8)
    ax.set_xlabel("Packets Logged")
    ax.grid(axis='x', color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
    plt.tight_layout(pad=0.8)
    return fig


# 6. Top destination ports
def plot_top_destination_ports(data: pd.DataFrame, limit=7):
    dst_col = _col(data, 'destination_port', 'dst_port')
    if data is None or data.empty or not dst_col:
        return _no_data_fig("Top Destination Ports")
    valid_data = data[dst_col].dropna()
    if valid_data.empty:
        return _no_data_fig("Top Destination Ports")
    counts = valid_data.astype(int).astype(str).value_counts().head(limit).sort_values(ascending=True)
    if counts.empty:
        return _no_data_fig("Top Destination Ports")
    fig, ax = _setup_fig()
    ax.barh(counts.index, counts.values, color='#ffd000', height=0.55)
    for idx, val in enumerate(counts.values):
        ax.text(val + 0.1, idx, f"{int(val)}", va='center', color=TEXT_COLOR, fontsize=7.5)
    ax.set_title(f"Top {limit} Targeted Ports", pad=8)
    ax.set_xlabel("Hits")
    ax.set_ylabel("Port")
    ax.grid(axis='x', color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
    plt.tight_layout(pad=0.8)
    return fig


# 7. Detection rule distribution
def plot_detection_rule_distribution(data: pd.DataFrame):
    rule_col = _col(data, 'rule_name', 'rule_id')
    if data is None or data.empty or not rule_col:
        return _no_data_fig("Detection Rule Distribution")
    counts = data[rule_col].dropna().value_counts().sort_values(ascending=True)
    if counts.empty:
        return _no_data_fig("Detection Rule Distribution")
    fig, ax = _setup_fig()
    ax.barh(counts.index, counts.values, color='#ff6b00', height=0.55)
    for idx, val in enumerate(counts.values):
        ax.text(val + 0.1, idx, f"{int(val)}", va='center', color=TEXT_COLOR, fontsize=7.5)
    ax.set_title("Alerts by Rule Triggered", pad=8)
    ax.set_xlabel("Count")
    ax.grid(axis='x', color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
    plt.tight_layout(pad=0.8)
    return fig


# 8. Unique destination ports per source IP
def plot_unique_dest_ports_per_source(data: pd.DataFrame, limit=7):
    src_col = _col(data, 'source_ip', 'src_ip')
    dst_col = _col(data, 'destination_port', 'dst_port')
    if data is None or data.empty or not src_col or not dst_col:
        return _no_data_fig("Unique Ports per Source")
    valid = data.dropna(subset=[src_col, dst_col])
    if valid.empty:
        return _no_data_fig("Unique Ports per Source")
    counts = valid.groupby(src_col)[dst_col].nunique().sort_values(ascending=True).tail(limit)
    if counts.empty:
        return _no_data_fig("Unique Ports per Source")
    fig, ax = _setup_fig()
    ax.barh(counts.index, counts.values, color='#e056fd', height=0.55)
    for idx, val in enumerate(counts.values):
        ax.text(val + 0.1, idx, f"{int(val)}", va='center', color=TEXT_COLOR, fontsize=7.5)
    ax.set_title("Unique Ports Scanned per Source", pad=8)
    ax.set_xlabel("Unique Port Count")
    ax.grid(axis='x', color=GRID_COLOR, linestyle='--', alpha=0.6, linewidth=0.7)
    plt.tight_layout(pad=0.8)
    return fig


def plot_connection_frequency(data: pd.DataFrame):
    return plot_top_source_ips(data)
