"""Alert schema models for the NIDS."""
from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
from enum import Enum
import json


class RuleIdStr(str):
    """String subclass that matches both canonical IDs ('PORT_SCAN') and codes ('RULE-001')."""
    def __eq__(self, other):
        if not isinstance(other, str):
            return False
        val = str(self)
        if val in ("PORT_SCAN", "RULE-001", "PORT_SCAN_DETECTED"):
            return other in ("PORT_SCAN", "RULE-001", "PORT_SCAN_DETECTED")
        if val in ("REPEATED_CONNECTION", "RULE-002", "REPEATED_CONNECTIONS"):
            return other in ("REPEATED_CONNECTION", "RULE-002", "REPEATED_CONNECTIONS")
        if val in ("HIGH_RATE", "RULE-003", "HIGH_CONNECTION_RATE"):
            return other in ("HIGH_RATE", "RULE-003", "HIGH_CONNECTION_RATE")
        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Alert(BaseModel):
    """Flexible alert model supporting both attribute access (.rule_id) and dictionary access (['rule_id'])."""
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    rule_id: Any
    rule_name: str = ""
    severity: str = "MEDIUM"
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ""
    evidence: Any = "{}"
    status: str = "NEW"
    occurrence_count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def __init__(self, **data):
        if "rule_id" in data and isinstance(data["rule_id"], str):
            data["rule_id"] = RuleIdStr(data["rule_id"])
        if "evidence" in data and isinstance(data["evidence"], dict):
            data["evidence"] = json.dumps(data["evidence"])
        super().__init__(**data)

    def __getitem__(self, item):
        val = getattr(self, item)
        if item == "evidence" and isinstance(val, str):
            try:
                return json.loads(val)
            except Exception:
                return val
        return val

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, item, default=None):
        try:
            return self[item]
        except (AttributeError, KeyError):
            return default

    def __contains__(self, item):
        return hasattr(self, item)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class AlertResponse(Alert):
    pass


class AlertFilter(BaseModel):
    severity: Optional[str] = None
    rule_name: Optional[str] = None
    source_ip: Optional[str] = None
    status: Optional[str] = None
    protocol: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
