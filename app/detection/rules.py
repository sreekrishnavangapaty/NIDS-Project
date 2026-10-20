from app.schemas.packet_schema import NetworkEvent
from app.schemas.alert_schema import RuleIdStr, Alert
from app.detection import thresholds
from typing import List, Dict, Any
from collections import defaultdict
import json


class DetectionRule:
    def __init__(self, rule_id: str, rule_name: str, description: str, severity: str, threshold: int, time_window: int, recommendation: str, code: str = ""):
        self.rule_id = RuleIdStr(rule_id)
        self.rule_name = rule_name
        self.code = code or rule_id
        self.description = description
        self.severity = severity
        self.threshold = threshold
        self.time_window = time_window
        self.recommendation = recommendation

    def check(self, events_window: List[NetworkEvent]) -> List[Alert]:
        return []


class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="PORT_SCAN",
            rule_name="Port Scan Detected",
            code="RULE-001",
            description="Detects a single source IP connecting to multiple unique destination ports on a destination IP within a short time window.",
            severity="HIGH",
            threshold=thresholds.get_port_scan_threshold(),
            time_window=thresholds.get_port_scan_window(),
            recommendation="Investigate source IP for reconnaissance/scanning activity. Block source if unauthorized."
        )

    def check(self, events_window: List[NetworkEvent]) -> List[Alert]:
        alerts = []
        scan_map = defaultdict(lambda: defaultdict(set))
        for event in events_window:
            if event.destination_port is not None:
                scan_map[event.source_ip][event.destination_ip].add(event.destination_port)

        for src, dests in scan_map.items():
            for dst, ports in dests.items():
                if len(ports) >= self.threshold:
                    desc = f"Source IP {src} attempted connections to {len(ports)} unique destination ports on {dst} within {self.time_window} seconds, exceeding the configured threshold of {self.threshold}."
                    evidence = {
                        "unique_ports_count": len(ports),
                        "ports": sorted(list(ports))[:50],
                        "threshold": self.threshold,
                        "window_seconds": self.time_window
                    }
                    alerts.append(Alert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        source_ip=src,
                        destination_ip=dst,
                        destination_port=None,
                        protocol="TCP",
                        description=desc,
                        evidence=evidence,
                    ))
        return alerts


class RepeatedConnectionRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="REPEATED_CONNECTION",
            rule_name="Repeated Connections",
            code="RULE-002",
            description="Detects a source IP repeatedly connecting to the same destination IP and port.",
            severity="MEDIUM",
            threshold=thresholds.get_repeated_connection_threshold(),
            time_window=thresholds.get_repeated_connection_window(),
            recommendation="Check if destination service is experiencing brute-force or authentication attacks."
        )

    def check(self, events_window: List[NetworkEvent]) -> List[Alert]:
        alerts = []
        conn_map = defaultdict(int)
        for event in events_window:
            if event.destination_port is not None:
                conn_map[(event.source_ip, event.destination_ip, event.destination_port)] += 1

        for (src, dst, dport), count in conn_map.items():
            if count >= self.threshold:
                desc = f"Source IP {src} connected to {dst}:{dport} {count} times within {self.time_window} seconds, exceeding threshold of {self.threshold}."
                evidence = {
                    "connection_count": count,
                    "attempt_count": count,
                    "threshold": self.threshold,
                    "window_seconds": self.time_window
                }
                alerts.append(Alert(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    source_ip=src,
                    destination_ip=dst,
                    destination_port=dport,
                    protocol="TCP",
                    description=desc,
                    evidence=evidence,
                ))
        return alerts


class HighConnectionRateRule(DetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="HIGH_RATE",
            rule_name="High Connection Rate",
            code="RULE-003",
            description="Detects unusually high total connection volume from a single source IP.",
            severity="CRITICAL",
            threshold=thresholds.get_high_rate_threshold(),
            time_window=thresholds.get_high_rate_window(),
            recommendation="Possible DoS or flood attack. Consider immediate rate limiting or firewall drop."
        )

    def check(self, events_window: List[NetworkEvent]) -> List[Alert]:
        alerts = []
        rate_map = defaultdict(int)
        for event in events_window:
            rate_map[event.source_ip] += 1

        for src, count in rate_map.items():
            if count >= self.threshold:
                desc = f"Source IP {src} generated {count} connections within {self.time_window} seconds, exceeding threshold of {self.threshold}."
                evidence = {
                    "total_connections": count,
                    "connection_count": count,
                    "threshold": self.threshold,
                    "window_seconds": self.time_window
                }
                alerts.append(Alert(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    source_ip=src,
                    destination_ip=None,
                    destination_port=None,
                    protocol="TCP",
                    description=desc,
                    evidence=evidence,
                ))
        return alerts
