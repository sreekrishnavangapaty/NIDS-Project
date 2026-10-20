import pytest
import json
from app.schemas.alert_schema import Alert
from datetime import datetime

def test_alert_creation(alert_manager, sample_port_scan_events):
    event = sample_port_scan_events[0]
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='PORT_SCAN',
        severity='HIGH',
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        description='Port scan detected',
        evidence=json.dumps({"ports_scanned": 15})
    )
    alert_manager.process_alert(alert)
    db_alerts = alert_manager.repository.get_alerts()
    assert len(db_alerts) == 1
    assert db_alerts[0]['rule_id'] == 'PORT_SCAN'

def test_alert_severity(alert_manager, sample_repeated_events):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='REPEATED_CONNECTION',
        severity='MEDIUM',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='Repeated connections',
        evidence='{}'
    )
    alert_manager.process_alert(alert)
    db_alerts = alert_manager.repository.get_alerts()
    assert db_alerts[0]['severity'] == 'MEDIUM'

def test_alert_evidence_content(alert_manager):
    evidence_dict = {"count": 50, "window": "10s"}
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='HIGH_RATE',
        severity='CRITICAL',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='High rate',
        evidence=json.dumps(evidence_dict)
    )
    alert_manager.process_alert(alert)
    db_alert = alert_manager.repository.get_alerts()[0]
    db_evidence = json.loads(db_alert['evidence'])
    assert 'count' in db_evidence
    assert db_evidence['count'] == 50

def test_alert_deduplication(alert_manager):
    alert1 = Alert(
        timestamp=datetime.now(),
        rule_id='PORT_SCAN',
        severity='HIGH',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='Port scan',
        evidence='{}'
    )
    alert_manager.process_alert(alert1)
    
    alert2 = Alert(
        timestamp=datetime.now(),
        rule_id='PORT_SCAN',
        severity='HIGH',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='Port scan again',
        evidence='{}'
    )
    alert_manager.process_alert(alert2)
    
    db_alerts = alert_manager.repository.get_alerts()
    assert len(db_alerts) == 1
    assert db_alerts[0]['occurrence_count'] == 2

def test_alert_status_update(alert_manager):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='PORT_SCAN',
        severity='HIGH',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='Port scan',
        evidence='{}'
    )
    alert_manager.process_alert(alert)
    db_alert = alert_manager.repository.get_alerts()[0]
    
    alert_manager.update_alert_status(db_alert['id'], 'INVESTIGATING')
    updated = alert_manager.repository.get_alert_by_id(db_alert['id'])
    assert updated['status'] == 'INVESTIGATING'

def test_alert_first_last_seen(alert_manager):
    t1 = datetime.now()
    alert1 = Alert(
        timestamp=t1,
        rule_id='PORT_SCAN',
        severity='HIGH',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='Port scan',
        evidence='{}'
    )
    alert_manager.process_alert(alert1)
    
    t2 = t1 = datetime.now()
    alert2 = Alert(
        timestamp=t2,
        rule_id='PORT_SCAN',
        severity='HIGH',
        source_ip='10.0.0.1',
        destination_ip='10.0.0.2',
        description='Port scan',
        evidence='{}'
    )
    alert_manager.process_alert(alert2)
    
    db_alert = alert_manager.repository.get_alerts()[0]
    assert db_alert['first_seen'] != db_alert['last_seen']
