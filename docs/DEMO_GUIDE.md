# NIDS Demonstration & Testing Guide

This guide describes how to run and verify the Network Intrusion Detection System (NIDS) in controlled lab and demonstration environments.

---

## 1. Overview of Demo Scenarios

The NIDS features a **genuinely functional pipeline**:
```text
Simulated / Real Traffic
           ↓
     Packet Parser
           ↓
   Feature Extraction
           ↓
    Detection Engine
           ↓
     Alert Manager
           ↓
    SQLite (nids.db)
           ↓
   Streamlit Dashboard
```

No synthetic alerts are inserted directly into the database. Every scenario emits raw network packets that travel through the exact same feature extraction and detection engine as live traffic.

---

## 2. Running Scenarios via CLI

The system provides two utility scripts in the `scripts/` directory:
- `scripts/test_port_scan.py`: Mandatory 13-port controlled scan verification.
- `scripts/generate_demo_traffic.py`: CLI traffic generator for all scenarios.
- `scripts/run_demo.py`: High-level wrapper with configurable attack counts.

### Scenario A: Mandatory 13-Port Controlled Scan (RULE-001)
Simulates a classic reconnaissance port scan targeting 13 well-known services on an authorized local IP:
- Ports: `20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080`
- Threshold: 10 unique ports within 10 seconds.

```bash
python scripts/test_port_scan.py
```

**Expected Result:**
- Output confirms:
  - 13 SYN packets generated
  - Feature extraction identified 13 unique ports and 13 SYN flags
  - Detection Engine fired `PORT_SCAN` / `RULE-001`
  - High severity alert persisted in SQLite database `data/nids.db`
  - Complete JSON evidence with scanned ports list

### Scenario B: Repeated Connection Attempts / Brute Force (RULE-002)
Simulates repeated connection attempts against a single service (e.g., SSH port 22):
- Threshold: 10 connection attempts within 30 seconds.

```bash
python scripts/generate_demo_traffic.py --mode repeated_connections --count 25
```

**Expected Result:**
- Emits 25 TCP SYN packets to port 22 from `10.0.0.100`.
- Fires `REPEATED_CONNECTION` alert with Medium severity.
- Persists evidence: `{"connection_count": 25, "threshold": 10, ...}`.

### Scenario C: High Connection Rate / Flood (RULE-003)
Simulates an unusually high volume of connections originating from one host:
- Threshold: 50 connections within 10 seconds.

```bash
python scripts/generate_demo_traffic.py --mode high_rate --count 65
```

**Expected Result:**
- Emits 65 rapid packets across subnet IPs from `10.0.0.200`.
- Fires `HIGH_RATE` alert with Critical severity.
- Persists evidence: `{"total_connections": 65, "threshold": 50, ...}`.

### Scenario D: Normal Background Traffic (Baseline)
Simulates benign HTTP, HTTPS, and DNS traffic:

```bash
python scripts/generate_demo_traffic.py --mode normal --count 50
```

**Expected Result:**
- 50 events logged to `network_events`.
- **0 alerts triggered** (verifies false positive suppression).

### Scenario E: Mixed Traffic
Combines normal background flows with intermittent attack bursts:

```bash
python scripts/generate_demo_traffic.py --mode mixed --count 100
```

---

## 3. Running Scenarios via the Streamlit UI

1. Launch the dashboard:
   ```bash
   streamlit run dashboard/app.py
   ```
2. Navigate to **"Live Monitoring"** in the left sidebar.
3. Select the **"Safe Demo Attack Simulator"** tab.
4. Choose the desired scenario from the dropdown:
   - `Port Scan (13 destination ports — triggers RULE-001)`
   - `Repeated Connections (SSH brute force — triggers RULE-002)`
   - `High Connection Rate (Flood traffic — triggers RULE-003)`
   - `Normal Network Traffic (HTTP/DNS/HTTPS — 0 alerts)`
   - `Mixed Traffic`
5. Adjust the packet count slider and click **"Run Scenario"**.
6. The success notification displays the exact number of events processed and alerts triggered.
7. Click **"Security Alerts"** or **"Alert Investigation"** in the sidebar to review the forensic details and update alert status.

---

## 4. Verifying SQLite Persistence

Verify that the SQLite database has recorded the events:

```bash
python -c "from app.database.repository import DatabaseRepository; repo = DatabaseRepository(); print('Stats:', repo.get_statistics())"
```

You can also export CSV reports directly from the **Security Alerts** or **Traffic Analysis** pages.
