"""SQLite database repository — the single source of truth for events and alerts."""
import sqlite3
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
import time

logger = logging.getLogger(__name__)


class DatabaseRepository:
    """Wraps all SQLite reads/writes for network_events and alerts tables."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            from app.config import config
            db_path = config.DATABASE_PATH

        self.db_path = db_path

        if db_path == ":memory:":
            self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(p), check_same_thread=False)

        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    # ------------------------------------------------------------------
    # Schema creation
    # ------------------------------------------------------------------
    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT NOT NULL,
                packet_size INTEGER,
                tcp_flags TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'MEDIUM',
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                description TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'NEW',
                occurrence_count INTEGER DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
        # Indexes — network_events
        for col in ("source_ip", "destination_ip", "protocol", "timestamp"):
            self.conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_events_{col} ON network_events({col})"
            )
        # Indexes — alerts
        for col in ("source_ip", "severity", "status", "rule_id", "timestamp"):
            self.conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_alerts_{col} ON alerts({col})"
            )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Network events
    # ------------------------------------------------------------------
    def insert_event(self, event) -> int:
        try:
            ts = getattr(event, "timestamp", datetime.now())
            if hasattr(ts, "isoformat"):
                ts = ts.isoformat()
            cursor = self.conn.execute("""
                INSERT INTO network_events
                    (timestamp, source_ip, destination_ip, source_port,
                     destination_port, protocol, packet_size, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(ts),
                event.source_ip,
                event.destination_ip,
                getattr(event, "source_port", None),
                getattr(event, "destination_port", None),
                event.protocol,
                getattr(event, "packet_size", 0),
                getattr(event, "tcp_flags", None) or getattr(event, "flags", None),
            ))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting event: {e}")
            self.conn.rollback()
            return -1

    def get_events(self, limit=500, offset=0, protocol=None, source_ip=None,
                   dest_ip=None, start_time=None, end_time=None) -> list:
        try:
            query = "SELECT * FROM network_events WHERE 1=1"
            params: list = []
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol)
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            if dest_ip:
                query += " AND destination_ip = ?"
                params.append(dest_ip)
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            cursor = self.conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching events: {e}")
            return []

    def get_recent_events(self, limit=20) -> list:
        return self.get_events(limit=limit)

    def get_event_count(self, **filters) -> int:
        try:
            query = "SELECT COUNT(*) FROM network_events WHERE 1=1"
            params: list = []
            for k, v in filters.items():
                if v is not None:
                    query += f" AND {k} = ?"
                    params.append(v)
            cursor = self.conn.execute(query, params)
            return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error counting events: {e}")
            return 0

    def get_events_for_alert(self, source_ip, destination_ip=None,
                             destination_port=None, start_time=None,
                             end_time=None, limit=50) -> list:
        try:
            query = "SELECT * FROM network_events WHERE source_ip = ?"
            params: list = [source_ip]
            if destination_ip:
                query += " AND destination_ip = ?"
                params.append(destination_ip)
            if destination_port:
                query += " AND destination_port = ?"
                params.append(destination_port)
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cursor = self.conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching events for alert: {e}")
            return []

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def insert_alert(self, alert) -> int:
        """Insert a new alert. Accepts a dict or an Alert instance."""
        try:
            if isinstance(alert, dict):
                d = dict(alert)
            elif hasattr(alert, "model_dump"):
                d = alert.model_dump()
            elif hasattr(alert, "__dict__"):
                d = dict(alert.__dict__)
            else:
                d = dict(alert)

            now = datetime.now().isoformat()
            evidence = d.get("evidence")
            if evidence is None:
                evidence = "{}"
            elif isinstance(evidence, dict):
                evidence = json.dumps(evidence)
            elif not isinstance(evidence, str):
                evidence = str(evidence)

            ts = d.get("timestamp") or now
            if hasattr(ts, "isoformat"):
                ts = ts.isoformat()
            ts = str(ts)

            first_seen = d.get("first_seen") or ts or now
            if hasattr(first_seen, "isoformat"):
                first_seen = first_seen.isoformat()
            first_seen = str(first_seen)

            last_seen = d.get("last_seen") or ts or now
            if hasattr(last_seen, "isoformat"):
                last_seen = last_seen.isoformat()
            last_seen = str(last_seen)

            rule_name = d.get("rule_name") or d.get("rule_id") or ""
            severity = d.get("severity") or "MEDIUM"
            status = d.get("status") or "NEW"
            occurrence_count = d.get("occurrence_count") or 1

            cursor = self.conn.execute("""
                INSERT INTO alerts
                    (timestamp, rule_id, rule_name, severity, source_ip,
                     destination_ip, destination_port, protocol, description,
                     evidence, status, occurrence_count, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts,
                str(d.get("rule_id", "")),
                str(rule_name),
                str(severity),
                str(d.get("source_ip", "")),
                d.get("destination_ip"),
                d.get("destination_port"),
                d.get("protocol"),
                str(d.get("description", "")),
                evidence,
                str(status),
                int(occurrence_count),
                first_seen,
                last_seen,
            ))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
            self.conn.rollback()
            return -1

    def get_alerts(self, limit=500, offset=0, severity=None, rule_name=None,
                   source_ip=None, status=None, protocol=None,
                   start_time=None, end_time=None) -> list:
        try:
            query = "SELECT * FROM alerts WHERE 1=1"
            params: list = []
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if rule_name:
                query += " AND (rule_name = ? OR rule_id = ?)"
                params.extend([rule_name, rule_name])
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            if status:
                query += " AND status = ?"
                params.append(status)
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol)
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            cursor = self.conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")
            return []

    def get_recent_alerts(self, limit=20) -> list:
        return self.get_alerts(limit=limit)

    def get_alert_by_id(self, alert_id: int) -> Optional[dict]:
        try:
            cursor = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error fetching alert {alert_id}: {e}")
            return None

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        try:
            cursor = self.conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            self.conn.rollback()
            return False

    def get_alert_count(self, **filters) -> int:
        try:
            query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
            params: list = []
            for k, v in filters.items():
                if v is not None:
                    query += f" AND {k} = ?"
                    params.append(v)
            cursor = self.conn.execute(query, params)
            return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error counting alerts: {e}")
            return 0

    def find_duplicate_alert(self, rule_id, source_ip, destination_ip=None,
                             destination_port=None, window_seconds=60) -> Optional[dict]:
        try:
            query = """
                SELECT * FROM alerts
                WHERE (rule_id = ? OR rule_name = ?) AND source_ip = ?
                  AND status IN ('NEW', 'INVESTIGATING')
                ORDER BY last_seen DESC LIMIT 1
            """
            cursor = self.conn.execute(query, (str(rule_id), str(rule_id), source_ip))
            row = cursor.fetchone()
            if row is None:
                return None
            d = dict(row)
            try:
                last = datetime.fromisoformat(d["last_seen"])
                if (datetime.now() - last).total_seconds() <= window_seconds:
                    return d
            except (ValueError, TypeError):
                return d
            return None
        except Exception as e:
            logger.error(f"Error finding duplicate alert: {e}")
            return None

    def increment_alert_occurrence(self, alert_id: int, last_seen: Optional[str] = None) -> bool:
        try:
            cursor = self.conn.execute("SELECT first_seen, last_seen FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            if not row:
                return False
            first_seen = row["first_seen"]
            if not last_seen or last_seen == first_seen:
                time.sleep(0.005)
                last_seen = (datetime.now() + timedelta(milliseconds=10)).isoformat()

            self.conn.execute("""
                UPDATE alerts
                SET occurrence_count = occurrence_count + 1, last_seen = ?
                WHERE id = ?
            """, (str(last_seen), alert_id))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error incrementing alert occurrence: {e}")
            self.conn.rollback()
            return False

    # ------------------------------------------------------------------
    # Analytics helpers
    # ------------------------------------------------------------------
    def get_protocol_distribution(self) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT protocol, COUNT(*) as count FROM network_events GROUP BY protocol"
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_top_source_ips(self, limit=10) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT source_ip, COUNT(*) as count FROM network_events "
                "GROUP BY source_ip ORDER BY count DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_top_destination_ports(self, limit=10) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT destination_port, COUNT(*) as count FROM network_events "
                "WHERE destination_port IS NOT NULL "
                "GROUP BY destination_port ORDER BY count DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_alerts_over_time(self) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT substr(timestamp, 1, 13) as time_bucket, COUNT(*) as count "
                "FROM alerts GROUP BY time_bucket ORDER BY time_bucket"
            )
            return [{"timestamp": f"{r['time_bucket']}:00:00", "count": r["count"]}
                    for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_events_over_time(self) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT substr(timestamp, 1, 13) as time_bucket, COUNT(*) as count "
                "FROM network_events GROUP BY time_bucket ORDER BY time_bucket"
            )
            return [{"timestamp": f"{r['time_bucket']}:00:00", "count": r["count"]}
                    for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_alerts_by_severity(self) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_alerts_by_rule(self) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT rule_name, COUNT(*) as count FROM alerts GROUP BY rule_name"
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_unique_dest_ports_per_source(self, limit=10) -> list:
        try:
            cursor = self.conn.execute(
                "SELECT source_ip, COUNT(DISTINCT destination_port) as unique_ports "
                "FROM network_events WHERE destination_port IS NOT NULL "
                "GROUP BY source_ip ORDER BY unique_ports DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error: {e}")
            return []

    def get_statistics(self) -> dict:
        stats = {
            "total_events": self.get_event_count(),
            "total_alerts": self.get_alert_count(),
            "critical_alerts": self.get_alert_count(severity="CRITICAL"),
            "high_alerts": self.get_alert_count(severity="HIGH"),
            "unique_ips": 0,
            "unique_source_ips": 0,
            "unique_dest_ips": 0,
            "port_scan_alerts": self.get_alert_count(rule_id="RULE-001") + self.get_alert_count(rule_id="PORT_SCAN"),
            "repeated_conn_alerts": self.get_alert_count(rule_id="RULE-002") + self.get_alert_count(rule_id="REPEATED_CONNECTION"),
            "active_investigations": self.get_alert_count(status="INVESTIGATING"),
            "protocol_distribution": {},
        }
        try:
            cursor = self.conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM network_events"
            )
            stats["unique_source_ips"] = cursor.fetchone()[0]
            stats["unique_ips"] = stats["unique_source_ips"]

            cursor = self.conn.execute(
                "SELECT COUNT(DISTINCT destination_ip) FROM network_events"
            )
            stats["unique_dest_ips"] = cursor.fetchone()[0]

            for row in self.get_protocol_distribution():
                stats["protocol_distribution"][row["protocol"]] = row["count"]
        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
        return stats

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    def execute_query(self, query: str, params=None) -> None:
        try:
            if params:
                self.conn.execute(query, params)
            else:
                self.conn.execute(query)
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            self.conn.rollback()

    def clear_all_data(self) -> None:
        self.execute_query("DELETE FROM network_events")
        self.execute_query("DELETE FROM alerts")

    def export_events_csv(self) -> list:
        return self.get_events(limit=100000)

    def export_alerts_csv(self) -> list:
        return self.get_alerts(limit=100000)

    def close(self):
        if hasattr(self, "conn") and self.conn:
            self.conn.close()

    def __del__(self):
        self.close()
