"""Tests for high connection rate detection — RULE-003."""
import pytest
from datetime import datetime, timedelta
from app.detection.engine import DetectionEngine
from app.schemas.packet_schema import NetworkEvent


def _high_rate_events(count, src="10.0.0.200"):
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(milliseconds=i * 50),
            source_ip=src,
            destination_ip=f"192.168.1.{100 + (i % 50)}",
            source_port=44444,
            destination_port=80,
            protocol="TCP",
            packet_size=100,
            tcp_flags="S",
        )
        for i in range(count)
    ]


class TestHighConnectionRateDetection:
    def test_triggers(self):
        engine = DetectionEngine()
        alerts = []
        for event in _high_rate_events(65):
            alerts.extend(engine.process(event))
        assert any(a["rule_id"] == "RULE-003" for a in alerts)

    def test_evidence(self):
        engine = DetectionEngine()
        alerts = []
        for event in _high_rate_events(60):
            alerts.extend(engine.process(event))
        hr = next((a for a in alerts if a["rule_id"] == "RULE-003"), None)
        assert hr is not None
        assert hr["evidence"]["total_connections"] >= 50

    def test_below_threshold(self):
        engine = DetectionEngine()
        alerts = []
        for event in _high_rate_events(20):
            alerts.extend(engine.process(event))
        assert not any(a["rule_id"] == "RULE-003" for a in alerts)

    def test_description(self):
        engine = DetectionEngine()
        alerts = []
        for event in _high_rate_events(55):
            alerts.extend(engine.process(event))
        hr = next((a for a in alerts if a["rule_id"] == "RULE-003"), None)
        assert hr is not None
        assert "10.0.0.200" in hr["description"]
        assert "connections" in hr["description"].lower()
