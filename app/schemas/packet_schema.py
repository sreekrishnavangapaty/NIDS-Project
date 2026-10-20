from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class NetworkEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    packet_size: int
    tcp_flags: Optional[str] = None

class NetworkEventResponse(NetworkEvent):
    id: int

class CaptureConfig(BaseModel):
    interface: str
    duration: int
    count: int
    filter_protocol: Optional[str] = None
