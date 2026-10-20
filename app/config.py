import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    DATABASE_PATH: str = os.getenv('NIDS_DATABASE_PATH', 'data/nids.db')
    LOG_LEVEL: str = os.getenv('NIDS_LOG_LEVEL', 'INFO')
    CAPTURE_INTERFACE: str = os.getenv('NIDS_CAPTURE_INTERFACE', 'eth0')
    CAPTURE_DURATION: int = int(os.getenv('NIDS_CAPTURE_DURATION', '60'))
    CAPTURE_COUNT: int = int(os.getenv('NIDS_CAPTURE_COUNT', '1000'))
    PORT_SCAN_THRESHOLD: int = int(os.getenv('NIDS_PORT_SCAN_THRESHOLD', '10'))
    PORT_SCAN_WINDOW: int = int(os.getenv('NIDS_PORT_SCAN_WINDOW', '10'))
    REPEATED_CONNECTION_THRESHOLD: int = int(os.getenv('NIDS_REPEATED_CONN_THRESHOLD', '10'))
    REPEATED_CONNECTION_WINDOW: int = int(os.getenv('NIDS_REPEATED_CONN_WINDOW', '30'))
    HIGH_RATE_THRESHOLD: int = int(os.getenv('NIDS_HIGH_RATE_THRESHOLD', '50'))
    HIGH_RATE_WINDOW: int = int(os.getenv('NIDS_HIGH_RATE_WINDOW', '10'))
    DEMO_MODE: bool = os.getenv('NIDS_DEMO_MODE', 'True').lower() in ('true', '1', 't')
    ALERT_DEDUP_WINDOW: int = int(os.getenv('NIDS_ALERT_DEDUP_WINDOW', '60'))

# Singleton instance
config = Config()
