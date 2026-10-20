"""Pytest fixtures shared across all NIDS tests."""
import sys
import os
import pytest
from datetime import datetime, timedelta

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database.repository import DatabaseRepository
from app.detection.engine import DetectionEngine
from app.alerts.alert_manager import AlertManager
from app.schemas.packet_schema import NetworkEvent


@pytest.fixture
def temp_db():
    """In-memory SQLite repository for isolated tests."""
    repo = DatabaseRepository(":memory:")
    yield repo
    repo.close()


@pytest.fixture
def detection_engine():
    return DetectionEngine()


@pytest.fixture
def alert_manager(temp_db):
    return AlertManager(temp_db)


# ---------------------------------------------------------------
# Sample event generators
# ---------------------------------------------------------------
@pytest.fixture
def sample_normal_events():
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(seconds=i),
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            source_port=12345 + i,
            destination_port=80,
            protocol="TCP",
            packet_size=200,
            tcp_flags="PA",
        )
        for i in range(5)
    ]


@pytest.fixture
def sample_port_scan_events():
    """20 SYN packets from one source to 20 different ports — should trigger port scan."""
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(milliseconds=i * 100),
            source_ip="10.0.0.50",
            destination_ip="192.168.1.100",
            source_port=54321,
            destination_port=i + 1,
            protocol="TCP",
            packet_size=64,
            tcp_flags="S",
        )
        for i in range(20)
    ]


@pytest.fixture
def sample_repeated_events():
    """25 SYN packets to the same destination port (SSH)."""
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(milliseconds=i * 100),
            source_ip="10.0.0.100",
            destination_ip="192.168.1.50",
            source_port=33333 + i,
            destination_port=22,
            protocol="TCP",
            packet_size=74,
            tcp_flags="S",
        )
        for i in range(25)
    ]


@pytest.fixture
def sample_high_rate_events():
    """65 rapid packets from one source — should trigger high connection rate."""
    base = datetime.now()
    return [
        NetworkEvent(
            timestamp=base + timedelta(milliseconds=i * 50),
            source_ip="10.0.0.200",
            destination_ip=f"192.168.1.{100 + (i % 50)}",
            source_port=44444,
            destination_port=80,
            protocol="TCP",
            packet_size=100,
            tcp_flags="S",
        )
        for i in range(65)
    ]
