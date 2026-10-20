import pytest
from app.detection.engine import DetectionEngine

def test_normal_traffic_no_alerts(detection_engine, sample_normal_events):
    alerts = []
    for event in sample_normal_events:
        alerts.extend(detection_engine.process(event))
    assert len(alerts) == 0

def test_port_scan_detected(detection_engine, sample_port_scan_events):
    alerts = []
    for event in sample_port_scan_events:
        alerts.extend(detection_engine.process(event))
    assert len(alerts) > 0
    assert any(a.rule_id == 'PORT_SCAN' for a in alerts)

def test_port_scan_evidence(detection_engine, sample_port_scan_events):
    alerts = []
    for event in sample_port_scan_events:
        alerts.extend(detection_engine.process(event))
    scan_alert = next((a for a in alerts if a.rule_id == 'PORT_SCAN'), None)
    assert scan_alert is not None
    assert scan_alert.source_ip == '10.0.0.50'
    assert 'ports' in scan_alert.description.lower() or 'threshold' in scan_alert.description.lower()

def test_repeated_connection_detected(detection_engine, sample_repeated_events):
    alerts = []
    for event in sample_repeated_events:
        alerts.extend(detection_engine.process(event))
    assert len(alerts) > 0
    assert any(a.rule_id == 'REPEATED_CONNECTION' for a in alerts)

def test_repeated_connection_evidence(detection_engine, sample_repeated_events):
    alerts = []
    for event in sample_repeated_events:
        alerts.extend(detection_engine.process(event))
    rep_alert = next((a for a in alerts if a.rule_id == 'REPEATED_CONNECTION'), None)
    assert rep_alert is not None
    assert 'attempt' in rep_alert.evidence.lower() or 'count' in rep_alert.evidence.lower()

def test_high_rate_detected(detection_engine, sample_high_rate_events):
    alerts = []
    for event in sample_high_rate_events:
        alerts.extend(detection_engine.process(event))
    assert len(alerts) > 0
    assert any(a.rule_id == 'HIGH_RATE' for a in alerts)

def test_below_threshold_no_alert(detection_engine, sample_port_scan_events):
    alerts = []
    # Process only 5 events (below default threshold of 10 for port scan)
    for event in sample_port_scan_events[:5]:
        alerts.extend(detection_engine.process(event))
    assert len(alerts) == 0

def test_engine_rules_info(detection_engine):
    rules_info = detection_engine.get_rules_info()
    assert len(rules_info) == 3
    rule_ids = [r['id'] for r in rules_info]
    assert 'PORT_SCAN' in rule_ids
    assert 'REPEATED_CONNECTION' in rule_ids
    assert 'HIGH_RATE' in rule_ids

def test_engine_reset(detection_engine, sample_port_scan_events):
    for event in sample_port_scan_events[:5]:
        detection_engine.process(event)
    
    detection_engine.reset()
    
    # Process the rest. Because we reset, it shouldn't trigger if the rest are < threshold
    alerts = []
    for event in sample_port_scan_events[5:10]:
        alerts.extend(detection_engine.process(event))
    assert len(alerts) == 0
