"""Tests for repeated connection detection — RULE-002."""
import pytest
from datetime import datetime, timedelta
from app.detection.engine import DetectionEngine
from app.schemas.packet_schema import NetworkEvent


def _repeated_events(count, src="10.0.0.100", dst="192.168.1.50", dport=22):
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(milliseconds=i * 100),
            source_ip=src,
            destination_ip=dst,
            source_port=33333 + i,
            destination_port=dport,
            protocol="TCP",
            packet_size=74,
            tcp_flags="S",
        )
        for i in range(count)
    ]


class TestRepeatedConnectionDetection:
    def test_triggers(self):
        """Repeated connections above threshold must trigger RULE-002."""
        engine = DetectionEngine()
        alerts = []
        for event in _repeated_events(15):
            alerts.extend(engine.process(event))
        assert any(a["rule_id"] == "RULE-002" for a in alerts)

    def test_evidence(self):
        engine = DetectionEngine()
        alerts = []
        for event in _repeated_events(20):
            alerts.extend(engine.process(event))
        rep = next((a for a in alerts if a["rule_id"] == "RULE-002"), None)
        assert rep is not None
        assert rep["source_ip"] == "10.0.0.100"
        assert rep["evidence"]["connection_count"] >= 10

    def test_below_threshold(self):
        engine = DetectionEngine()
        alerts = []
        for event in _repeated_events(5):
            alerts.extend(engine.process(event))
        assert not any(a["rule_id"] == "RULE-002" for a in alerts)

    def test_different_ports_no_trigger(self):
        """Connections to different ports should NOT trigger repeated-connection rule."""
        engine = DetectionEngine()
        base = datetime.now()
        events = [
            NetworkEvent(
                timestamp=base + timedelta(milliseconds=i * 100),
                source_ip="10.0.0.100",
                destination_ip="192.168.1.50",
                source_port=33333,
                destination_port=i + 1,  # different port each time
                protocol="TCP",
                packet_size=74,
                tcp_flags="S",
            )
            for i in range(15)
        ]
        alerts = []
        for event in events:
            alerts.extend(engine.process(event))
        # Should not trigger repeated connection (different ports)
        assert not any(a["rule_id"] == "RULE-002" for a in alerts)
