from dataclasses import dataclass
from typing import Optional

@dataclass
class NetworkEventModel:
    id: int
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_size: int
    tcp_flags: Optional[str]

@dataclass
class AlertModel:
    id: int
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    source_ip: str
    destination_ip: Optional[str]
    destination_port: Optional[int]
    protocol: Optional[str]
    description: str
    evidence: str
    status: str
    occurrence_count: int
    first_seen: str
    last_seen: str
