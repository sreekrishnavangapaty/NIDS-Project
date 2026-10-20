"""Detection engine — processes network events through all registered rules."""
from collections import deque, defaultdict
from typing import List, Dict, Any
from datetime import datetime, timedelta

from app.schemas.packet_schema import NetworkEvent
from app.schemas.alert_schema import Alert, RuleIdStr
from app.detection.rules import PortScanRule, RepeatedConnectionRule, HighConnectionRateRule


class DetectionEngine:
    def __init__(self):
        self.rules = [
            PortScanRule(),
            RepeatedConnectionRule(),
            HighConnectionRateRule(),
        ]
        self.event_buffer: deque = deque(maxlen=50000)
        self._fired: dict = defaultdict(lambda: None)

    def process(self, event: NetworkEvent) -> List[Alert]:
        return self.process_event(event)

    def process_event(self, event: NetworkEvent) -> List[Alert]:
        self.event_buffer.append(event)
        generated_alerts: List[Alert] = []

        for rule in self.rules:
            cutoff = event.timestamp - timedelta(seconds=rule.time_window)
            window_events = [
                e for e in self.event_buffer
                if e.timestamp >= cutoff
            ]

            raw_alerts = rule.check(window_events)

            for alert in raw_alerts:
                key = (str(alert.rule_id), alert.source_ip, alert.destination_ip or "")
                last_fired = self._fired.get(key)

                if last_fired is None or (event.timestamp - last_fired).total_seconds() > rule.time_window:
                    alert.timestamp = event.timestamp
                    alert.first_seen = event.timestamp
                    alert.last_seen = event.timestamp
                    generated_alerts.append(alert)
                    self._fired[key] = event.timestamp

        return generated_alerts

    def get_rules_info(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": RuleIdStr(r.rule_id),
                "rule_id": RuleIdStr(r.rule_id),
                "rule_name": r.rule_name,
                "code": r.code,
                "description": r.description,
                "severity": r.severity,
                "threshold": r.threshold,
                "time_window": r.time_window,
                "recommendation": r.recommendation,
            }
            for r in self.rules
        ]

    def reset(self):
        self.event_buffer.clear()
        self._fired.clear()

    def update_thresholds(self, **kwargs):
        mapping = {
            "port_scan_threshold": ("PORT_SCAN", "threshold"),
            "port_scan_window": ("PORT_SCAN", "time_window"),
            "repeated_conn_threshold": ("REPEATED_CONNECTION", "threshold"),
            "repeated_conn_window": ("REPEATED_CONNECTION", "time_window"),
            "high_rate_threshold": ("HIGH_RATE", "threshold"),
            "high_rate_window": ("HIGH_RATE", "time_window"),
        }
        rule_map = {r.rule_id: r for r in self.rules}
        for key, value in kwargs.items():
            if key in mapping and value is not None:
                rid, attr = mapping[key]
                for r in self.rules:
                    if r.rule_id == rid or r.code == rid:
                        setattr(r, attr, int(value))
