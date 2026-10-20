"""Alert manager — processes, deduplicates, and persists security alerts."""
import json
import logging
from typing import List, Optional
from datetime import datetime

from app.config import config

logger = logging.getLogger(__name__)


class AlertManager:
    """Sits between the detection engine and the database repository.

    Responsibilities:
    - Accept raw alert dicts from the engine
    - Deduplicate within a configurable window
    - Insert new alerts or increment occurrence_count on existing ones
    - Provide alert investigation helpers
    """

    def __init__(self, repository):
        self.repository = repository
        self.alerts_generated = 0

    # ------------------------------------------------------------------
    # Primary interface
    # ------------------------------------------------------------------
    def process_alert(self, alert) -> Optional[int]:
        """Process a single alert (dict or Alert-like object).

        Returns the alert id (new or existing).
        """
        if isinstance(alert, dict):
            d = alert
        elif hasattr(alert, "model_dump"):
            d = alert.model_dump()
        else:
            d = alert.__dict__

        return self._upsert(d)

    def process_alerts(self, alerts: list) -> List[int]:
        """Process a batch of alerts.  Returns list of alert ids."""
        ids = []
        for a in alerts:
            aid = self.process_alert(a)
            if aid and aid > 0:
                ids.append(aid)
        return ids

    # Alias used by some dashboard code
    def handle_alert(self, alert) -> Optional[int]:
        return self.process_alert(alert)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _upsert(self, d: dict) -> int:
        """Insert a new alert or increment an existing duplicate."""
        rule_id = d.get("rule_id", "")
        source_ip = d.get("source_ip", "")
        dest_ip = d.get("destination_ip")
        dest_port = d.get("destination_port")

        # Look for a recent duplicate
        dup = self.repository.find_duplicate_alert(
            rule_id=rule_id,
            source_ip=source_ip,
            destination_ip=dest_ip,
            destination_port=dest_port,
            window_seconds=config.ALERT_DEDUP_WINDOW,
        )

        now = datetime.now().isoformat()

        if dup:
            self.repository.increment_alert_occurrence(dup["id"], now)
            return dup["id"]

        # Ensure evidence is a JSON string
        evidence = d.get("evidence", "{}")
        if isinstance(evidence, dict):
            evidence = json.dumps(evidence)

        ts = d.get("timestamp", now)
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()

        new_alert = {
            "timestamp": ts,
            "rule_id": rule_id,
            "rule_name": d.get("rule_name", ""),
            "severity": d.get("severity", "MEDIUM"),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "destination_port": dest_port,
            "protocol": d.get("protocol"),
            "description": d.get("description", ""),
            "evidence": evidence,
            "status": "NEW",
            "occurrence_count": 1,
            "first_seen": d.get("first_seen", now),
            "last_seen": d.get("last_seen", now),
        }

        aid = self.repository.insert_alert(new_alert)
        if aid > 0:
            self.alerts_generated += 1
        return aid

    # ------------------------------------------------------------------
    # Investigation helpers
    # ------------------------------------------------------------------
    def get_alert_details(self, alert_id: int) -> dict:
        alert = self.repository.get_alert_by_id(alert_id)
        if not alert:
            return {}

        related = self.repository.get_events_for_alert(
            source_ip=alert["source_ip"],
            destination_ip=alert.get("destination_ip"),
            destination_port=alert.get("destination_port"),
            limit=50,
        )
        alert["related_events"] = related
        return alert

    def update_status(self, alert_id: int, status: str) -> bool:
        return self.repository.update_alert_status(alert_id, status)

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Alias for update_status."""
        return self.update_status(alert_id, status)
