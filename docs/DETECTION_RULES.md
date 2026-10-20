# Detection Rules Specification & Tuning Manual

This document details the active detection algorithms, default thresholds, evidence payload schemas, and false-positive tuning strategies for the Network Intrusion Detection System (NIDS).

---

## RULE-001: Port Scan Detection (`PORT_SCAN`)

### Conceptual Model
Attackers conduct port scans during the reconnaissance phase to identify open ports, listening network services, and operating system fingerprints.

### Algorithm & Mathematical Logic
- **Input**: A stream of `NetworkEvent` objects within a sliding time window $T_{\text{scan}}$.
- **Grouping**: Group events by source IP and target IP: $\mathcal{G}_{\text{src, dst}} = \{ e \in W \mid e.\text{src} = s \land e.\text{dst} = d \}$.
- **Metric**: Number of distinct destination ports contacted:
  $$N_{\text{ports}}(s, d) = |\{ e.\text{dport} \mid e \in \mathcal{G}_{\text{src, dst}} \land e.\text{dport} \neq \text{None} \}|$$
- **Trigger Condition**:
  $$N_{\text{ports}}(s, d) \ge \text{PORT\_SCAN\_THRESHOLD}$$

### Operational Parameters
- **Rule ID**: `PORT_SCAN` / `RULE-001`
- **Default Severity**: `HIGH`
- **Default Threshold**: 10 unique destination ports
- **Default Window ($T_{\text{scan}}$)**: 10 seconds
- **Evidence Structure**:
  ```json
  {
    "unique_ports_count": 13,
    "ports": [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080],
    "threshold": 10,
    "window_seconds": 10
  }
  ```

### Tuning & False Positive Mitigation
- **Legitimate Scanners**: Whitelist authorized internal vulnerability scanners (e.g., Nessus, Tenable, Qualys) or network monitoring appliances.
- **CDN / Multi-Service Workstations**: If clients contact diverse services across brief intervals, increase the threshold to 20 ports or decrease the correlation window to 5 seconds.

---

## RULE-002: Repeated Connection Attempts (`REPEATED_CONNECTION`)

### Conceptual Model
Targeted attacks (such as brute-force password guessing against SSH on port 22 or RDP on port 3389) manifest as rapid, repetitive connection attempts directed at a single destination port from a single source.

### Algorithm & Mathematical Logic
- **Input**: Sliding window $T_{\text{repeat}}$.
- **Grouping**: Group events by source IP, target IP, and target destination port: $\mathcal{G}_{\text{src, dst, dport}}$.
- **Metric**: Total connection count:
  $$C(s, d, p) = |\mathcal{G}_{\text{src, dst, dport}}|$$
- **Trigger Condition**:
  $$C(s, d, p) \ge \text{REPEATED\_CONNECTION\_THRESHOLD}$$

### Operational Parameters
- **Rule ID**: `REPEATED_CONNECTION` / `RULE-002`
- **Default Severity**: `MEDIUM`
- **Default Threshold**: 10 connection attempts
- **Default Window ($T_{\text{repeat}}$)**: 30 seconds
- **Evidence Structure**:
  ```json
  {
    "connection_count": 15,
    "attempt_count": 15,
    "threshold": 10,
    "window_seconds": 30
  }
  ```

### Tuning & False Positive Mitigation
- **Misconfigured Polling Clients**: In environments with aggressive API polling or database connection pools lacking keep-alive, increase the threshold to 30 attempts.

---

## RULE-003: High Connection Rate (`HIGH_RATE`)

### Conceptual Model
Detects flood denial-of-service (DoS) attempts, SYN floods, or rapidly propagating malware worms that initiate high-frequency outbound connections regardless of destination port.

### Algorithm & Mathematical Logic
- **Input**: Sliding window $T_{\text{rate}}$.
- **Grouping**: Total outbound connections initiated by source IP: $\mathcal{G}_{\text{src}}$.
- **Metric**: Total packet count from source:
  $$C_{\text{rate}}(s) = |\mathcal{G}_{\text{src}}|$$
- **Trigger Condition**:
  $$C_{\text{rate}}(s) \ge \text{HIGH\_RATE\_THRESHOLD}$$

### Operational Parameters
- **Rule ID**: `HIGH_RATE` / `RULE-003`
- **Default Severity**: `CRITICAL`
- **Default Threshold**: 50 connections
- **Default Window ($T_{\text{rate}}$)**: 10 seconds
- **Evidence Structure**:
  ```json
  {
    "total_connections": 65,
    "connection_count": 65,
    "threshold": 50,
    "window_seconds": 10
  }
  ```

---

## Adding New Detection Rules

1. Subclass `DetectionRule` in `app/detection/rules.py`.
2. Implement the `check(self, events_window: List[NetworkEvent]) -> List[Alert]` method.
3. Register the rule in `DetectionEngine.__init__` (`app/detection/engine.py`).
4. Add threshold getters in `app/detection/thresholds.py` and defaults in `app/config.py`.
