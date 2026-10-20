"""Controlled Port Scan Test — Rule 001 Verification.

Simulates a realistic port scan hitting 13 standard network ports
(20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080)
against an authorized local target.

Verifies the entire pipeline:
PACKET/EVENT -> FEATURE EXTRACTION -> DETECTION ENGINE -> ALERT MANAGER -> SQLITE
"""
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database.connection import init_db
from app.database.repository import DatabaseRepository
from app.detection.engine import DetectionEngine
from app.alerts.alert_manager import AlertManager
from app.features.extractor import FeatureExtractor
from app.schemas.packet_schema import NetworkEvent


def run_controlled_port_scan():
    print("=" * 60)
    print("NIDS CONTROLLED PORT SCAN VERIFICATION (RULE 001)")
    print("=" * 60)

    # 1. Target and ports setup
    source_ip = "192.168.1.55"
    target_ip = "192.168.1.1"
    scan_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080]

    print(f"[*] Attacker Source IP : {source_ip}")
    print(f"[*] Target Destination IP: {target_ip}")
    print(f"[*] Destination Ports ({len(scan_ports)}): {scan_ports}")
    print(f"[*] Detection Threshold: 10 ports within 10-second window")

    # 2. Initialize pipeline components
    repo = DatabaseRepository()
    engine = DetectionEngine()
    alert_mgr = AlertManager(repo)

    # Record initial counts
    initial_alerts_count = repo.get_alert_count()
    initial_events_count = repo.get_event_count()

    # 3. Generate packets
    base_time = datetime.now()
    generated_events = []
    print("\n[+] Generating SYN packet sequence...")
    for i, port in enumerate(scan_ports):
        ev = NetworkEvent(
            timestamp=base_time + timedelta(milliseconds=i * 200),
            source_ip=source_ip,
            destination_ip=target_ip,
            source_port=49152 + i,
            destination_port=port,
            protocol="TCP",
            packet_size=60,
            tcp_flags="SYN"
        )
        generated_events.append(ev)

    # 4. Feature Extraction Check
    print("[+] Extracting features via FeatureExtractor layer...")
    window_features = FeatureExtractor.extract_window_features(generated_events, source_ip)
    print(f"    - Packets analyzed: {window_features.packet_count}")
    print(f"    - Unique destination ports: {window_features.unique_destination_ports}")
    print(f"    - SYN packets count: {window_features.syn_count}")
    print(f"    - Window duration: {window_features.window_seconds:.2f}s")

    # 5. Process through Detection Engine and Alert Manager
    print("\n[+] Feeding events through Detection Engine and Alert Manager...")
    alerts_captured = []
    for ev in generated_events:
        repo.insert_event(ev)
        alerts = engine.process(ev)
        for a in alerts:
            aid = alert_mgr.process_alert(a)
            alerts_captured.append((aid, a))

    # 6. Verify in SQLite Database
    print("\n[+] Verifying persistence in SQLite database...")
    latest_alerts = repo.get_alerts(limit=5, source_ip=source_ip)
    assert len(latest_alerts) > 0, "ERROR: No alert found in SQLite database!"

    scan_alert = next((a for a in latest_alerts if a['rule_id'] in ('PORT_SCAN', 'RULE-001')), None)
    assert scan_alert is not None, "ERROR: PORT_SCAN alert not found in SQLite!"

    print("\n" + "=" * 60)
    print("SUCCESS: REAL PORT SCAN ALERT DETECTED AND VERIFIED!")
    print("=" * 60)
    print(f"Alert ID        : {scan_alert['id']}")
    print(f"Rule ID         : {scan_alert['rule_id']}")
    print(f"Rule Name       : {scan_alert['rule_name']}")
    print(f"Severity        : {scan_alert['severity']}")
    print(f"Source IP       : {scan_alert['source_ip']}")
    print(f"Destination IP  : {scan_alert['destination_ip']}")
    print(f"Status          : {scan_alert['status']}")
    print(f"First Seen      : {scan_alert['first_seen']}")
    print(f"Last Seen       : {scan_alert['last_seen']}")
    print(f"Occurrence Count: {scan_alert['occurrence_count']}")
    print(f"Description     : {scan_alert['description']}")
    
    evidence = scan_alert['evidence']
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            pass
    print(f"Evidence Details: {json.dumps(evidence, indent=2)}")

    related_events = repo.get_events_for_alert(source_ip=source_ip, destination_ip=target_ip, limit=20)
    print(f"Related Events in DB: {len(related_events)} network events logged for this scan.")
    print("=" * 60)
    return scan_alert


if __name__ == '__main__':
    run_controlled_port_scan()
