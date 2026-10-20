"""Tests for the feature extraction module."""
import pytest
from datetime import datetime, timedelta
from app.features.extractor import FeatureExtractor, EventFeatures, WindowFeatures
from app.schemas.packet_schema import NetworkEvent


def _make_event(src="10.0.0.1", dst="10.0.0.2", dport=80, proto="TCP",
                flags="S", offset_ms=0):
    return NetworkEvent(
        timestamp=datetime(2026, 1, 1) + timedelta(milliseconds=offset_ms),
        source_ip=src,
        destination_ip=dst,
        source_port=54321,
        destination_port=dport,
        protocol=proto,
        packet_size=64,
        tcp_flags=flags,
    )


class TestEventFeatures:
    def test_basic_extraction(self):
        e = _make_event()
        f = FeatureExtractor.extract_event_features(e)
        assert isinstance(f, EventFeatures)
        assert f.source_ip == "10.0.0.1"
        assert f.is_tcp is True
        assert f.is_syn is True

    def test_udp_event(self):
        e = _make_event(proto="UDP", flags="")
        f = FeatureExtractor.extract_event_features(e)
        assert f.is_udp is True
        assert f.is_tcp is False
        assert f.is_syn is False

    def test_icmp_event(self):
        e = _make_event(proto="ICMP", flags="", dport=None)
        f = FeatureExtractor.extract_event_features(e)
        assert f.is_icmp is True


class TestWindowFeatures:
    def test_port_scan_features(self):
        events = [_make_event(dport=i, offset_ms=i * 100) for i in range(15)]
        wf = FeatureExtractor.extract_window_features(events, "10.0.0.1")
        assert wf.unique_destination_ports == 15
        assert wf.packet_count == 15
        assert wf.syn_count == 15

    def test_connection_count(self):
        events = [_make_event(offset_ms=i * 50) for i in range(10)]
        wf = FeatureExtractor.extract_window_features(events, "10.0.0.1")
        assert wf.connection_count == 10

    def test_multiple_sources(self):
        events = [
            _make_event(src="A", offset_ms=0),
            _make_event(src="B", offset_ms=100),
            _make_event(src="A", offset_ms=200),
        ]
        all_features = FeatureExtractor.extract_all_window_features(events)
        assert "A" in all_features
        assert "B" in all_features
        assert all_features["A"].packet_count == 2
        assert all_features["B"].packet_count == 1

    def test_empty_events(self):
        wf = FeatureExtractor.extract_window_features([], "10.0.0.1")
        assert wf.packet_count == 0
        assert wf.unique_destination_ports == 0
