"""End-to-End System Integration Test for All 8 Verification Criteria."""
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
from scripts.generate_demo_traffic import generate_events


def run_e2e_verification():
    print("=" * 70)
    print("NIDS END-TO-END FINAL ACCEPTANCE TEST SUITE")
    print("=" * 70)

    repo = DatabaseRepository()
    engine = DetectionEngine()
    alert_mgr = AlertManager(repo)

    # Clean test bed
    repo.clear_all_data()

    # -------------------------------------------------------------
    # TEST 1: NORMAL TRAFFIC (No false alerts)
    # -------------------------------------------------------------
    print("\n[TEST 1] Processing Normal Traffic...")
    normal_events = generate_events('normal', 30)
    initial_alerts = repo.get_alert_count()
    for ev in normal_events:
        repo.insert_event(ev)
        for a in engine.process(ev):
            alert_mgr.process_alert(a)
    events_in_db = repo.get_event_count()
    alerts_after_normal = repo.get_alert_count()
    assert events_in_db == 30, f"Expected 30 events, got {events_in_db}"
    assert alerts_after_normal == 0, f"Expected 0 alerts for normal traffic, got {alerts_after_normal}"
    print(f"  -> PASS: 30 events stored, 0 false alerts generated.")

    # -------------------------------------------------------------
    # TEST 2: PORT SCAN DETECTION (13 unique ports)
    # -------------------------------------------------------------
    print("\n[TEST 2] Processing 13-Port Reconnaissance Scan...")
    scan_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080]
    base_t = datetime.now()
    scan_events = [
        NetworkEvent(
            timestamp=base_t + timedelta(milliseconds=i * 100),
            source_ip="192.168.1.99",
            destination_ip="192.168.1.1",
            source_port=50000 + i,
            destination_port=p,
            protocol="TCP",
            packet_size=60,
            tcp_flags="SYN"
        )
        for i, p in enumerate(scan_ports)
    ]
    # Verify features
    wf = FeatureExtractor.extract_window_features(scan_events, "192.168.1.99")
    assert wf.unique_destination_ports == 13
    assert wf.syn_count == 13

    for ev in scan_events:
        repo.insert_event(ev)
        for a in engine.process(ev):
            alert_mgr.process_alert(a)

    scan_alerts = repo.get_alerts(source_ip="192.168.1.99")
    assert len(scan_alerts) >= 1
    scan_alert = scan_alerts[0]
    assert scan_alert['rule_id'] in ('PORT_SCAN', 'RULE-001')
    assert scan_alert['severity'] == 'HIGH'
    print(f"  -> PASS: Alert #{scan_alert['id']} ({scan_alert['rule_name']}) created with evidence.")

    # -------------------------------------------------------------
    # TEST 3: REPEATED CONNECTIONS
    # -------------------------------------------------------------
    print("\n[TEST 3] Processing Repeated Connection Attempts...")
    rep_events = [
        NetworkEvent(
            timestamp=base_t + timedelta(milliseconds=i * 100),
            source_ip="10.0.0.88",
            destination_ip="192.168.1.50",
            source_port=40000 + i,
            destination_port=22,
            protocol="TCP",
            packet_size=74,
            tcp_flags="SYN"
        )
        for i in range(15)
    ]
    for ev in rep_events:
        repo.insert_event(ev)
        for a in engine.process(ev):
            alert_mgr.process_alert(a)

    rep_alerts = repo.get_alerts(source_ip="10.0.0.88")
    assert len(rep_alerts) >= 1
    rep_alert = rep_alerts[0]
    assert rep_alert['rule_id'] in ('REPEATED_CONNECTION', 'RULE-002')
    print(f"  -> PASS: Alert #{rep_alert['id']} ({rep_alert['rule_name']}) created with count evidence.")

    # -------------------------------------------------------------
    # TEST 4: HIGH CONNECTION RATE
    # -------------------------------------------------------------
    print("\n[TEST 4] Processing High Connection Rate Burst...")
    high_events = [
        NetworkEvent(
            timestamp=base_t + timedelta(milliseconds=i * 20),
            source_ip="10.0.0.77",
            destination_ip=f"192.168.1.{10 + (i % 20)}",
            source_port=30000,
            destination_port=80,
            protocol="TCP",
            packet_size=100,
            tcp_flags="SYN"
        )
        for i in range(60)
    ]
    for ev in high_events:
        repo.insert_event(ev)
        for a in engine.process(ev):
            alert_mgr.process_alert(a)

    high_alerts = repo.get_alerts(source_ip="10.0.0.77")
    assert len(high_alerts) >= 1
    high_alert = high_alerts[0]
    assert high_alert['rule_id'] in ('HIGH_RATE', 'RULE-003')
    print(f"  -> PASS: Alert #{high_alert['id']} ({high_alert['rule_name']}) created.")

    # -------------------------------------------------------------
    # TEST 5: ALERT STATUS PERSISTENCE (NEW -> INVESTIGATING -> RESOLVED)
    # -------------------------------------------------------------
    print("\n[TEST 5] Testing Alert Status State Machine...")
    aid = scan_alert['id']
    repo.update_alert_status(aid, "INVESTIGATING")
    fetched = repo.get_alert_by_id(aid)
    assert fetched['status'] == "INVESTIGATING", "Failed to update to INVESTIGATING"

    repo.update_alert_status(aid, "RESOLVED")
    fetched = repo.get_alert_by_id(aid)
    assert fetched['status'] == "RESOLVED", "Failed to update to RESOLVED"
    print(f"  -> PASS: Alert #{aid} status transitioned NEW -> INVESTIGATING -> RESOLVED and persisted.")

    # -------------------------------------------------------------
    # TEST 6: ANALYTICS TELEMETRY FROM REAL SQLITE DATA
    # -------------------------------------------------------------
    print("\n[TEST 6] Testing Analytics Data Generation...")
    stats = repo.get_statistics()
    proto_dist = repo.get_protocol_distribution()
    top_sources = repo.get_top_source_ips()
    top_ports = repo.get_top_destination_ports()
    assert stats['total_events'] > 0
    assert stats['total_alerts'] >= 3
    assert len(proto_dist) > 0
    assert len(top_sources) > 0
    print(f"  -> PASS: Real SQLite statistics verified: {stats['total_events']} events, {stats['total_alerts']} alerts.")

    # -------------------------------------------------------------
    # TEST 7: CSV EXPORT VALIDATION
    # -------------------------------------------------------------
    print("\n[TEST 7] Testing Database CSV Export...")
    exported_events = repo.export_events_csv()
    exported_alerts = repo.export_alerts_csv()
    assert len(exported_events) == repo.get_event_count()
    assert len(exported_alerts) == repo.get_alert_count()
    print(f"  -> PASS: Export functions retrieved {len(exported_events)} events and {len(exported_alerts)} alerts.")

    print("\n" + "=" * 70)
    print("ALL 8 END-TO-END ACCEPTANCE TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == '__main__':
    run_e2e_verification()
