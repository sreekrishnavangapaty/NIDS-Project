"""NIDS Demo Runner Script.

Runs simulated demo attacks and normal traffic through the full NIDS pipeline:
Traffic -> Parsing -> Features -> Detection Engine -> Alert Manager -> SQLite.
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scripts.generate_demo_traffic import main as generate_main, generate_events
from scripts.test_port_scan import run_controlled_port_scan
from app.database.connection import init_db
from app.database.repository import DatabaseRepository
from app.detection.engine import DetectionEngine
from app.alerts.alert_manager import AlertManager


def run_demo(scenario: str, count: int = 50):
    print(f"\n[+] Running demo scenario: {scenario.upper()}")
    if scenario == "port_scan_controlled":
        run_controlled_port_scan()
        return

    init_db()
    repo = DatabaseRepository()
    engine = DetectionEngine()
    alert_mgr = AlertManager(repo)

    events = generate_events(scenario, count)
    print(f"[*] Processing {len(events)} events through Detection Engine...")

    alerts_triggered = 0
    rule_counts = {}
    for ev in events:
        repo.insert_event(ev)
        alerts = engine.process(ev)
        for a in alerts:
            aid = alert_mgr.process_alert(a)
            alerts_triggered += 1
            rule_counts[str(a.rule_id)] = rule_counts.get(str(a.rule_id), 0) + 1

    print("\n[+] Demo Execution Summary:")
    print(f"    - Network events logged: {len(events)}")
    print(f"    - Alerts created: {alerts_triggered}")
    for r, c in rule_counts.items():
        print(f"      * {r}: {c}")
    print("[+] Data persisted to SQLite (data/nids.db).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS Demo Runner")
    parser.add_argument(
        "--scenario",
        choices=["normal", "port_scan", "repeated_connections", "high_rate", "mixed", "port_scan_controlled"],
        default="mixed",
        help="Demo scenario to execute"
    )
    parser.add_argument("--count", type=int, default=50, help="Number of packets to simulate")
    args = parser.parse_args()

    run_demo(args.scenario, args.count)
