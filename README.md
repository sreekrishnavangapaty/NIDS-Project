# 🛡️ NIDS — Network Intrusion Detection System

A high-performance, rule-based Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) Console implemented in Python with Scapy, SQLite, FastAPI, Streamlit, and Matplotlib.

---

## 1. Project Purpose

This NIDS monitors, parses, normalizes, and analyzes network traffic to detect unauthorized reconnaissance, brute force, and denial-of-service behaviors in real time. It is designed with clean architectural separation between packet acquisition, protocol decoding, feature extraction, detection algorithms, alert management, and analyst visualization.

---

## 2. System Architecture

The NIDS implements a genuinely functional 9-stage pipeline:

```text
[Live Network / Synthetic Traffic]
               │
               ▼
   [Scapy Packet Ingestion]       (Promiscuous interface / Raw sockets)
               │
               ▼
    [Protocol Packet Parser]      (TCP / UDP / ICMP header normalization)
               │
               ▼
      [Feature Extraction]        (SYN tracking, unique port aggregation)
               │
               ▼
    [Rule Detection Engine]       (RULE-001, RULE-002, RULE-003 correlation)
               │
               ▼
        [Alert Manager]           (Deduplication, severity scoring, forensics)
               │
               ▼
    [SQLite Persistent DB]        (network_events, alerts with WAL mode)
               │
               ▼
   [Analytics & Visualization]    (Aggregation queries + Matplotlib charts)
               │
               ▼
[Streamlit SOC & FastAPI Backend] (Command Center & SIEM REST API)
```

Every stage of the pipeline is fully functional. Demo and test traffic passes through the exact same feature extraction and detection engine as live packets.

---

## 3. Technology Stack & Dependencies

- **Language**: Python 3.9+ (tested on Python 3.13)
- **Packet Ingestion**: `scapy` (>= 2.5.0)
- **RESTful API**: `fastapi` (>= 0.100.0), `uvicorn` (>= 0.23.0)
- **Data Models**: `pydantic` (>= 2.0.0)
- **Storage**: `sqlite3` with Write-Ahead Logging (WAL) and column indexes
- **SOC Dashboard**: `streamlit` (>= 1.28.0)
- **Analytics Visualization**: `matplotlib` (>= 3.7.0) — *strictly Matplotlib, no Plotly*
- **Data Processing**: `pandas` (>= 2.0.0)
- **Testing**: `pytest` (>= 7.4.0), `httpx` (>= 0.24.0)

---

## 4. Installation & Setup

### Prerequisites
1. Python 3.9 or higher.
2. **Windows Specific**: For live packet sniffing, install [Npcap](https://npcap.com/) with *"Install Npcap in WinPcap API-compatible Mode"* enabled.
3. **Linux Specific**: Ensure `libpcap` is available (`sudo apt install libpcap-dev`).

### Environment Setup
```bash
# Clone the repository
git clone <repo-url>
cd nids-project

# Create and activate virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 5. Persistent SQLite Database Architecture

All CSV-based primary storage (`traffic_log.csv`, `alerts.csv`) has been replaced with an indexed relational SQLite database (`data/nids.db`). CSV format remains available exclusively as an export option.

### Schema:
- **`network_events`**: `id`, `timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `packet_size`, `tcp_flags`.
  - *Indexes*: `source_ip`, `destination_ip`, `protocol`, `timestamp`.
- **`alerts`**: `id`, `timestamp`, `rule_id`, `rule_name`, `severity`, `source_ip`, `destination_ip`, `destination_port`, `protocol`, `description`, `evidence`, `status`, `occurrence_count`, `first_seen`, `last_seen`.
  - *Indexes*: `source_ip`, `severity`, `status`, `rule_id`, `timestamp`.
  - *Status Lifecycle*: `NEW` → `INVESTIGATING` → `RESOLVED` / `FALSE_POSITIVE`.

---

## 6. Detection Rules & Logic

| Rule ID | Code | Rule Name | Severity | Default Threshold | Correlation Window | Description |
|---|---|---|---|---|---|---|
| `PORT_SCAN` | `RULE-001` | Port Scan Detected | `HIGH` | ≥ 10 unique ports | 10 seconds | Detects reconnaissance scans hitting multiple destination ports from a single source IP. |
| `REPEATED_CONNECTION` | `RULE-002` | Repeated Connections | `MEDIUM` | ≥ 10 attempts | 30 seconds | Detects brute-force attacks against a single service (e.g. SSH on port 22). |
| `HIGH_RATE` | `RULE-003` | High Connection Rate | `CRITICAL` | ≥ 50 connections | 10 seconds | Detects flood and denial-of-service traffic volume across targets. |

All thresholds and time correlation windows are centralized in `app/config.py` and configurable dynamically via the dashboard **Settings** page or environment variables.

---

## 7. Running the Application

### 1. Launch the Streamlit SOC Command Center
```bash
streamlit run dashboard/app.py
```
Access the dashboard at `http://localhost:8501`.

The dashboard includes 8 fully functional pages:
1. **Overview**: Live SOC metrics (total events, alerts by severity, port scan alerts, repeated connection alerts, active investigations) and timeline charts.
2. **Live Monitoring**: Controls for live Scapy sniffing and the Safe Demo Attack Simulator.
3. **Security Alerts**: Searchable, filterable alerts table with CSV export.
4. **Alert Investigation**: In-depth forensic view showing contributed packets, JSON evidence, guidance checklist, and status update controls (`NEW` → `INVESTIGATING` → `RESOLVED`).
5. **Traffic Analysis**: 8 Matplotlib charts depicting network trends, protocol distribution, top source IPs, top destination ports, and scan indicators.
6. **Detection Rules**: Exhaustive technical documentation of rules, threshold equations, and evidence structures.
7. **System Architecture**: Complete 9-stage architectural breakdown.
8. **Settings**: Centralized threshold tuning and database maintenance.

### 2. Launch the FastAPI Backend (Optional)
```bash
uvicorn app.main:app --reload --port 8000
```
Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

---

## 8. Safe Demo Mode & Controlled Testing

The system provides safe synthetic attack generators that route packets through the complete parser and detection pipeline:

```bash
# Run the critical 13-port controlled scan verification
python scripts/test_port_scan.py

# Run repeated connections demo (SSH brute force)
python scripts/generate_demo_traffic.py --mode repeated_connections --count 25

# Run high connection rate demo (DoS flood)
python scripts/generate_demo_traffic.py --mode high_rate --count 65

# Run normal baseline traffic (0 alerts generated)
python scripts/generate_demo_traffic.py --mode normal --count 50

# Run high-level demo menu
python scripts/run_demo.py --scenario mixed --count 100
```

---

## 9. Running Automated Tests

Run the complete test suite:

```bash
python -m pytest -v
```

The test suite contains 69 comprehensive tests covering:
- TCP, UDP, ICMP, and malformed packet parsing (`tests/test_packet_parser.py`, `tests/test_parser.py`)
- Feature extraction layer (`tests/test_features.py`)
- Port scan detection and evidence verification (`tests/test_port_scan.py`, `tests/test_detection.py`)
- Repeated connection attempt detection (`tests/test_repeated_connections.py`)
- High connection rate detection (`tests/test_high_connection_rate.py`)
- Alert creation, deduplication, and occurrence counting (`tests/test_alerts.py`)
- SQLite persistence, filtering, and transactions (`tests/test_database.py`)
- FastAPI REST API endpoints (`tests/test_api.py`)

---

## 10. Limitations

1. **High-Throughput Environments**: Python and Scapy packet capture is designed for low-to-medium throughput (lab/enterprise perimeter sampling). For gigabit line-rate capture, kernel-bypass technologies such as DPDK, AF_PACKET, or eBPF (as in Suricata/Snort) are recommended.
2. **Concurrent Database Writes**: SQLite operates with Write-Ahead Logging (WAL) for concurrent reads, but writes are serialized. For massive distributed ingestion, PostgreSQL or ClickHouse can be substituted.
3. **Encrypted Payloads**: The NIDS inspects Layer 3/4 headers. Deep payload inspection within TLS/HTTPS streams requires TLS termination or JA3/JA4 fingerprinting.

---

## 11. Ethical Use & Authorized Purpose

> **IMPORTANT**: This software is developed strictly for defensive monitoring, educational analysis, and authorized security auditing on private networks you own or have explicit written permission to monitor. Never run packet sniffing or port scanning against external systems without prior authorization.
