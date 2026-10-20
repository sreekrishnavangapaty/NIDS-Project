"""Feature extraction layer.

Sits between the packet parser and the detection engine.  Extracts
higher-level features from raw ``NetworkEvent`` objects that the
detection rules use for their decisions.

The extractor is deliberately kept *stateless* — all windowing and
aggregation is done by the detection rules themselves.  This module
normalises and enriches individual events.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from datetime import datetime, timedelta
from collections import defaultdict

from app.schemas.packet_schema import NetworkEvent


@dataclass
class EventFeatures:
    """Features extracted from a single network event."""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "UNKNOWN"
    packet_size: int = 0
    tcp_flags: Optional[str] = None
    is_syn: bool = False
    is_tcp: bool = False
    is_udp: bool = False
    is_icmp: bool = False


@dataclass
class WindowFeatures:
    """Aggregated features over a time window for a specific source IP."""
    source_ip: str
    packet_count: int = 0
    connection_count: int = 0
    unique_destination_ports: int = 0
    unique_destination_ips: int = 0
    syn_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    destination_ports: Set[int] = field(default_factory=set)
    destination_ips: Set[str] = field(default_factory=set)
    window_seconds: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class FeatureExtractor:
    """Extracts features from network events."""

    @staticmethod
    def extract_event_features(event: NetworkEvent) -> EventFeatures:
        """Extract features from a single event."""
        flags = getattr(event, "tcp_flags", None) or getattr(event, "flags", None) or ""
        is_syn = "S" in str(flags).upper() or "SYN" in str(flags).upper()

        return EventFeatures(
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=getattr(event, "source_port", None),
            destination_port=getattr(event, "destination_port", None),
            protocol=event.protocol,
            packet_size=getattr(event, "packet_size", 0),
            tcp_flags=str(flags) if flags else None,
            is_syn=is_syn,
            is_tcp=event.protocol == "TCP",
            is_udp=event.protocol == "UDP",
            is_icmp=event.protocol == "ICMP",
        )

    @staticmethod
    def extract_window_features(events: List[NetworkEvent],
                                source_ip: str) -> WindowFeatures:
        """Aggregate features for a source IP across a list of events."""
        src_events = [e for e in events if e.source_ip == source_ip]

        wf = WindowFeatures(source_ip=source_ip)
        wf.packet_count = len(src_events)

        for e in src_events:
            flags = getattr(e, "tcp_flags", None) or getattr(e, "flags", None) or ""
            is_syn = "S" in str(flags).upper() or "SYN" in str(flags).upper()

            if is_syn:
                wf.syn_count += 1
                wf.connection_count += 1
            elif e.protocol in ("TCP", "UDP"):
                wf.connection_count += 1

            if e.protocol == "TCP":
                wf.tcp_count += 1
            elif e.protocol == "UDP":
                wf.udp_count += 1
            elif e.protocol == "ICMP":
                wf.icmp_count += 1

            if getattr(e, "destination_port", None) is not None:
                wf.destination_ports.add(e.destination_port)
            wf.destination_ips.add(e.destination_ip)

            if wf.first_seen is None or e.timestamp < wf.first_seen:
                wf.first_seen = e.timestamp
            if wf.last_seen is None or e.timestamp > wf.last_seen:
                wf.last_seen = e.timestamp

        wf.unique_destination_ports = len(wf.destination_ports)
        wf.unique_destination_ips = len(wf.destination_ips)

        if wf.first_seen and wf.last_seen:
            wf.window_seconds = (wf.last_seen - wf.first_seen).total_seconds()

        return wf

    @staticmethod
    def extract_all_window_features(events: List[NetworkEvent]) -> Dict[str, WindowFeatures]:
        """Compute window features for every unique source IP in the event list."""
        sources = {e.source_ip for e in events}
        return {
            src: FeatureExtractor.extract_window_features(events, src)
            for src in sources
        }
