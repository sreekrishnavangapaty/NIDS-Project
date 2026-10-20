"""Tests for the packet parser."""
import pytest
from app.capture.packet_parser import PacketParser
from app.schemas.packet_schema import NetworkEvent
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestScapyParsing:
    def test_parse_tcp_packet(self):
        packet = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80, flags="S") / Raw(b"Hello")
        event = PacketParser.parse_scapy_packet(packet)
        assert event is not None
        assert event.source_ip == "1.2.3.4"
        assert event.destination_ip == "5.6.7.8"
        assert event.source_port == 12345
        assert event.destination_port == 80
        assert event.protocol == "TCP"
        assert "S" in (event.tcp_flags or "")

    def test_parse_udp_packet(self):
        packet = IP(src="8.8.8.8", dst="192.168.1.1") / UDP(sport=53, dport=44444) / Raw(b"DNS")
        event = PacketParser.parse_scapy_packet(packet)
        assert event is not None
        assert event.protocol == "UDP"
        assert event.source_port == 53
        assert event.destination_port == 44444

    def test_parse_icmp_packet(self):
        packet = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        event = PacketParser.parse_scapy_packet(packet)
        assert event is not None
        assert event.protocol == "ICMP"
        assert event.source_port is None
        assert event.destination_port is None

    def test_parse_missing_ip_layer(self):
        packet = TCP(sport=123, dport=456)
        event = PacketParser.parse_scapy_packet(packet)
        assert event is None

    def test_parse_tcp_flags(self):
        for flag in ("S", "A", "SA", "F", "R"):
            packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, flags=flag)
            event = PacketParser.parse_scapy_packet(packet)
            assert event is not None
            assert event.tcp_flags is not None


class TestRawParsing:
    def test_parse_raw_event(self):
        data = {
            "timestamp": datetime.now(),
            "source_ip": "1.1.1.1",
            "destination_ip": "2.2.2.2",
            "source_port": 1234,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_size": 100,
            "tcp_flags": "S",
        }
        event = PacketParser.parse_raw(data)
        assert isinstance(event, NetworkEvent)
        assert event.source_ip == "1.1.1.1"
        assert event.protocol == "TCP"

    def test_parse_raw_minimal(self):
        data = {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "ICMP",
        }
        event = PacketParser.parse_raw(data)
        assert event.source_port is None
        assert event.destination_port is None
