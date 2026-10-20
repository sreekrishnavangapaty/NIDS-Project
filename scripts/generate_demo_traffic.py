import sys
import os
import time
import random
import argparse
from datetime import datetime, timedelta

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database.connection import init_db
from app.database.repository import DatabaseRepository
from app.detection.engine import DetectionEngine
from app.alerts.alert_manager import AlertManager
from app.schemas.packet_schema import NetworkEvent

def generate_events(mode, count):
    events = []
    base_time = datetime.now()
    
    # Common IPs and ports
    normal_ips = [f"192.168.1.{i}" for i in range(10, 20)]
    normal_ports = [80, 443, 22, 53, 8080, 3306]
    
    if mode == 'normal' or mode == 'mixed':
        for i in range(count if mode == 'normal' else int(count * 0.4)):
            events.append(NetworkEvent(
                timestamp=base_time + timedelta(seconds=i*0.5),
                source_ip=random.choice(normal_ips),
                destination_ip=random.choice(normal_ips),
                source_port=random.randint(1024, 65535),
                destination_port=random.choice(normal_ports),
                protocol=random.choice(['TCP', 'UDP', 'ICMP']),
                packet_size=random.randint(64, 1500),
                flags=random.choice(['S', 'A', 'PA', '']),
                raw_data=b''
            ))
            
    if mode == 'port_scan' or mode == 'mixed':
        scan_src = "10.0.0.50"
        scan_dst = "192.168.1.100"
        scan_count = count if mode == 'port_scan' else int(count * 0.2)
        for i in range(scan_count):
            events.append(NetworkEvent(
                timestamp=base_time + timedelta(seconds=i*0.1),
                source_ip=scan_src,
                destination_ip=scan_dst,
                source_port=random.randint(1024, 65535),
                destination_port=i+1,
                protocol='TCP',
                packet_size=64,
                flags='S',
                raw_data=b''
            ))
            
    if mode == 'repeated_connections' or mode == 'mixed':
        rep_src = "10.0.0.100"
        rep_dst = "192.168.1.50"
        rep_count = count if mode == 'repeated_connections' else int(count * 0.2)
        for i in range(rep_count):
            events.append(NetworkEvent(
                timestamp=base_time + timedelta(seconds=i*0.2),
                source_ip=rep_src,
                destination_ip=rep_dst,
                source_port=random.randint(1024, 65535),
                destination_port=22,
                protocol='TCP',
                packet_size=74,
                flags='S',
                raw_data=b''
            ))
            
    if mode == 'high_rate' or mode == 'mixed':
        high_src = "10.0.0.200"
        high_count = count if mode == 'high_rate' else int(count * 0.2)
        for i in range(high_count):
            events.append(NetworkEvent(
                timestamp=base_time + timedelta(seconds=i*0.05),
                source_ip=high_src,
                destination_ip=f"192.168.1.{random.randint(100, 200)}",
                source_port=random.randint(1024, 65535),
                destination_port=random.choice(normal_ports),
                protocol=random.choice(['TCP', 'UDP']),
                packet_size=random.randint(64, 500),
                flags='S',
                raw_data=b''
            ))
            
    # Sort events by timestamp
    events.sort(key=lambda x: x.timestamp)
    return events

def main():
    parser = argparse.ArgumentParser(description="Generate demo network traffic")
    parser.add_argument('--mode', choices=['normal', 'port_scan', 'repeated_connections', 'high_rate', 'mixed'], required=True)
    parser.add_argument('--count', type=int, default=100, help='Number of events to generate')
    args = parser.parse_args()

    init_db()
    repo = DatabaseRepository()
    engine = DetectionEngine()
    alert_mgr = AlertManager(repo)
    
    events = generate_events(args.mode, args.count)
    
    print(f"Generating {len(events)} events in '{args.mode}' mode...")
    
    alerts_triggered = 0
    rule_breakdown = {}
    
    for event in events:
        repo.insert_event(event)
        alerts = engine.process(event)
        for alert in alerts:
            alert_mgr.process_alert(alert)
            alerts_triggered += 1
            rule_breakdown[alert.rule_id] = rule_breakdown.get(alert.rule_id, 0) + 1
            
    print(f"\nSummary:")
    print(f"Events generated: {len(events)}")
    print(f"Alerts triggered: {alerts_triggered}")
    for rule, count in rule_breakdown.items():
        print(f"  - {rule}: {count}")

if __name__ == '__main__':
    main()
