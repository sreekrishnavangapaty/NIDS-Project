"""Tests for port scan detection — RULE-001."""
import pytest
from datetime import datetime, timedelta
from app.detection.engine import DetectionEngine
from app.schemas.packet_schema import NetworkEvent


def _scan_events(num_ports, src="10.0.0.50", dst="192.168.1.100"):
    """Generate port-scan events hitting `num_ports` unique ports."""
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(milliseconds=i * 100),
            source_ip=src,
            destination_ip=dst,
            source_port=54321,
            destination_port=i + 1,
            protocol="TCP",
            packet_size=64,
            tcp_flags="S",
        )
        for i in range(num_ports)
    ]


class TestPortScanDetection:
    def test_port_scan_triggers(self):
        """Scanning >=10 unique ports must produce PORT_SCAN alert."""
        engine = DetectionEngine()
        alerts = []
        for event in _scan_events(15):
            alerts.extend(engine.process(event))
        assert len(alerts) > 0
        assert any(a["rule_id"] == "RULE-001" for a in alerts)

    def test_port_scan_evidence(self):
        engine = DetectionEngine()
        alerts = []
        for event in _scan_events(13):
            alerts.extend(engine.process(event))
        scan_alert = next((a for a in alerts if a["rule_id"] == "RULE-001"), None)
        assert scan_alert is not None
        assert scan_alert["source_ip"] == "10.0.0.50"
        evidence = scan_alert["evidence"]
        assert evidence["unique_ports_count"] >= 10
        assert "ports" in evidence
        assert evidence["threshold"] == 10

    def test_below_threshold_no_alert(self):
        """Fewer than 10 unique ports should NOT trigger."""
        engine = DetectionEngine()
        alerts = []
        for event in _scan_events(5):
            alerts.extend(engine.process(event))
        assert not any(a["rule_id"] == "RULE-001" for a in alerts)

    def test_port_scan_at_exact_threshold(self):
        """Exactly 10 ports should trigger (>= threshold)."""
        engine = DetectionEngine()
        alerts = []
        for event in _scan_events(10):
            alerts.extend(engine.process(event))
        assert any(a["rule_id"] == "RULE-001" for a in alerts)

    def test_port_scan_different_sources(self):
        """Two sources scanning 8 ports each should NOT trigger."""
        engine = DetectionEngine()
        alerts = []
        for event in _scan_events(8, src="A"):
            alerts.extend(engine.process(event))
        for event in _scan_events(8, src="B"):
            alerts.extend(engine.process(event))
        # Neither source reached 10 unique ports
        assert not any(a["rule_id"] == "RULE-001" for a in alerts)

    def test_port_scan_description_text(self):
        engine = DetectionEngine()
        alerts = []
        for event in _scan_events(12):
            alerts.extend(engine.process(event))
        scan_alert = next(a for a in alerts if a["rule_id"] == "RULE-001")
        assert "unique destination ports" in scan_alert["description"].lower()
        assert "10.0.0.50" in scan_alert["description"]
