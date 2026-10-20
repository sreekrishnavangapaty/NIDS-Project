"""Packet parser — converts raw Scapy packets into NetworkEvent objects.

Also provides a class-based ``PacketParser`` facade used by the test suite.
"""
from app.schemas.packet_schema import NetworkEvent
from datetime import datetime
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def parse_packet(packet) -> Optional[NetworkEvent]:
    """Parse a raw Scapy packet into a NetworkEvent."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if not packet.haslayer(IP):
            return None

        ip_layer = packet.getlayer(IP)
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        packet_size = len(packet)
        protocol = "UNKNOWN"
        source_port = None
        destination_port = None
        tcp_flags_str = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet.getlayer(TCP)
            source_port = tcp_layer.sport
            destination_port = tcp_layer.dport
            tcp_flags_str = str(tcp_layer.flags)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet.getlayer(UDP)
            source_port = udp_layer.sport
            destination_port = udp_layer.dport

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return NetworkEvent(
            timestamp=datetime.now(),
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=tcp_flags_str,
        )
    except Exception as e:
        logger.error(f"Error parsing packet: {e}")
        return None


def parse_raw_event(data: dict) -> NetworkEvent:
    """Create a NetworkEvent from a plain dict."""
    return NetworkEvent(
        timestamp=data.get("timestamp", datetime.now()),
        source_ip=data.get("source_ip", ""),
        destination_ip=data.get("destination_ip", ""),
        source_port=data.get("source_port"),
        destination_port=data.get("destination_port"),
        protocol=data.get("protocol", "UNKNOWN"),
        packet_size=data.get("packet_size", 0),
        tcp_flags=data.get("tcp_flags"),
    )


class PacketParser:
    """Class-based facade — delegates to the module-level functions.

    This exists so that the test suite can call ``PacketParser.parse_scapy_packet()``
    and ``PacketParser.parse_raw()`` as documented.
    """

    @staticmethod
    def parse_scapy_packet(packet) -> Optional[NetworkEvent]:
        return parse_packet(packet)

    @staticmethod
    def parse_raw(data: dict) -> NetworkEvent:
        return parse_raw_event(data)
