import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import get_db_connection
from app.database.repository import DatabaseRepository
from app.schemas.alert_schema import Alert
from datetime import datetime

client = TestClient(app)

@pytest.fixture(autouse=True)
def override_dependency(temp_db):
    app.dependency_overrides[DatabaseRepository] = lambda: temp_db
    yield
    app.dependency_overrides.clear()

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_get_alerts_empty(temp_db):
    response = client.get("/alerts")
    assert response.status_code == 200
    assert response.json() == []

def test_get_alerts_after_insert(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test alert',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    response = client.get("/alerts")
    assert response.status_code == 200
    assert len(response.json()) == 1

def test_get_alert_by_id(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_ID',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test id',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    alerts = temp_db.get_alerts()
    alert_id = alerts[0]['id']
    
    response = client.get(f"/alerts/{alert_id}")
    assert response.status_code == 200
    assert response.json()['id'] == alert_id

def test_get_alert_not_found():
    response = client.get("/alerts/99999")
    assert response.status_code == 404

def test_update_alert_status(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_ID',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test update',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    alerts = temp_db.get_alerts()
    alert_id = alerts[0]['id']
    
    response = client.patch(f"/alerts/{alert_id}/status", json={"status": "INVESTIGATING"})
    assert response.status_code == 200
    
    fetched = client.get(f"/alerts/{alert_id}").json()
    assert fetched['status'] == "INVESTIGATING"

def test_update_alert_invalid_status(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_ID',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test update',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    alerts = temp_db.get_alerts()
    alert_id = alerts[0]['id']
    
    response = client.patch(f"/alerts/{alert_id}/status", json={"status": "INVALID"})
    assert response.status_code == 400

def test_get_statistics(temp_db):
    response = client.get("/statistics")
    assert response.status_code == 200
    data = response.json()
    assert 'total_events' in data
    assert 'total_alerts' in data

def test_get_traffic(temp_db):
    response = client.get("/traffic")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
