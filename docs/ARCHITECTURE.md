# NIDS Architecture Specification

## 1. System Pipeline Overview
The Network Intrusion Detection System (NIDS) processes network traffic through a strictly layered, decoupled 9-stage pipeline:

```text
[Network Traffic / Demo Generator]
                │
                ▼
     [Scapy Capture Engine]       (Live raw socket / synthetic packets)
                │
                ▼
    [Protocol Packet Parser]      (TCP / UDP / ICMP header normalization)
                │
                ▼
      [Feature Extraction]        (SYN flag ratios, unique port sets, counts)
                │
                ▼
    [Rule Detection Engine]       (Sliding-window correlation: RULE 001-003)
                │
                ▼
        [Alert Manager]           (Deduplication, severity scoring, forensics)
                │
                ▼
    [SQLite Persistent DB]        (network_events, alerts with WAL indexing)
                │
                ▼
   [Analytics & Visualization]    (Pure Matplotlib telemetry charts)
                │
                ▼
 [Streamlit SOC & FastAPI API]    (Analyst triage console & REST endpoints)
```

---

## 2. Component Specifications

### 1. Packet Source & Ingestion (`app.capture.packet_capture`)
- **Live Mode**: Uses Scapy's non-blocking packet capture (`sniff`) bound to a user-specified interface (e.g. Ethernet, Wi-Fi, or loopback). Operates on a dedicated background thread.
- **Safe Demo Mode**: Generates synthetic, realistic TCP/UDP/ICMP packets with accurate timestamps, IP headers, TCP flags, and ports, without requiring elevated privileges.

### 2. Packet Parser (`app.capture.packet_parser`)
- Extracts IP layer (`src`, `dst`, packet length).
- Dissects Layer 4 protocols:
  - **TCP**: source port, destination port, control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
  - **UDP**: source port, destination port.
  - **ICMP**: type, code.
- Malformed, fragmented, or unexpected non-IP frames are gracefully captured and discarded without raising unhandled exceptions.

### 3. Feature Extraction (`app.features.extractor`)
Decouples raw packet parsing from detection logic:
- **Per-Event Features**: `is_syn`, `is_tcp`, `is_udp`, `is_icmp`, flags, packet size.
- **Windowed Features**: Aggregated across sliding time windows for a given source IP:
  - `packet_count`
  - `connection_count`
  - `unique_destination_ports`
  - `unique_destination_ips`
  - `syn_count`
  - `window_seconds`

### 4. Detection Engine (`app.detection.engine` & `rules`)
Maintains an internal event ring buffer and evaluates sliding windows:
- **RULE-001 (Port Scan Detection)**: Detects a source IP targeting ≥ 10 unique destination ports within 10 seconds.
- **RULE-002 (Repeated Connections)**: Detects ≥ 10 connection attempts to the same destination service within 30 seconds.
- **RULE-003 (High Connection Rate)**: Detects ≥ 50 connection attempts across targets within 10 seconds.

### 5. Alert Manager (`app.alerts.alert_manager`)
- Assigns unique alert identifiers.
- Scores severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- Synthesizes forensic evidence dictionaries (ports targeted, counts, thresholds, timestamps).
- Deduplicates recurring events within a sliding window (default 60s) to prevent SOC alert flooding.
- Tracks `first_seen`, `last_seen`, and increments `occurrence_count`.

### 6. SQLite Persistent Database (`app.database.repository`)
Replaces flat CSV files (`traffic_log.csv`, `alerts.csv`) as primary persistent storage:
- **`network_events` Table**: stores timestamped records of every parsed event. Indexed on `source_ip`, `destination_ip`, `protocol`, and `timestamp`.
- **`alerts` Table**: stores detected intrusion alerts. Indexed on `source_ip`, `severity`, `status`, `rule_id`, and `timestamp`.
- SQLite operates in WAL (Write-Ahead Logging) mode with `check_same_thread=False` for thread-safe concurrent reads.

### 7. Analytics & Visualization Engine (`app.analytics.statistics` & `dashboard.components.charts`)
- Strictly utilizes **Matplotlib** for rendering dark-themed SOC telemetry charts:
  - Network events over time (per minute)
  - Security alerts over time
  - Alerts by severity breakdown
  - Protocol distribution (Pie)
  - Top source IPs by volume
  - Top destination ports targeted
  - Detection rule distribution
  - Unique destination ports contacted per source IP (scan indicator)
- Safe fallback when data tables are empty or sparse.

### 8. Presentation Layer (`dashboard/app.py` & `app.main`)
- **Streamlit SOC Dashboard**: Provides 8 dedicated SOC pages: Overview, Live Monitoring, Security Alerts, Alert Investigation, Traffic Analysis, Detection Rules, System Architecture, and Settings.
- **FastAPI REST API**: Serves JSON endpoints (`/health`, `/alerts`, `/alerts/{id}`, `/alerts/{id}/status`, `/traffic`, `/statistics`) for integration with external SIEM systems.
