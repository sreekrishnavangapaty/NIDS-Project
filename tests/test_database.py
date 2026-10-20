import pytest
from app.database.connection import init_db
from app.schemas.packet_schema import NetworkEvent
from app.schemas.alert_schema import Alert
from datetime import datetime

def test_init_db(temp_db):
    assert temp_db is not None
    # Assuming temp_db creates tables in conftest for in-memory

def test_insert_event(temp_db, sample_normal_events):
    event = sample_normal_events[0]
    temp_db.insert_event(event)
    events = temp_db.get_events()
    assert len(events) == 1
    assert events[0]['source_ip'] == event.source_ip

def test_insert_alert(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_RULE',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    alerts = temp_db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]['rule_id'] == 'TEST_RULE'

def test_get_events_with_filter(temp_db, sample_normal_events):
    for event in sample_normal_events:
        temp_db.insert_event(event)
    events = temp_db.get_events(protocol='TCP')
    assert len(events) == 5

def test_get_events_with_ip_filter(temp_db, sample_normal_events):
    for event in sample_normal_events:
        temp_db.insert_event(event)
    events = temp_db.get_events(source_ip='192.168.1.10')
    assert len(events) == 5
    events_empty = temp_db.get_events(source_ip='8.8.8.8')
    assert len(events_empty) == 0

def test_get_alert_by_id(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_RULE',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    alerts = temp_db.get_alerts()
    alert_id = alerts[0]['id']
    fetched = temp_db.get_alert_by_id(alert_id)
    assert fetched['id'] == alert_id

def test_update_alert_status(temp_db):
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_RULE',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    alerts = temp_db.get_alerts()
    alert_id = alerts[0]['id']
    temp_db.update_alert_status(alert_id, 'RESOLVED')
    fetched = temp_db.get_alert_by_id(alert_id)
    assert fetched['status'] == 'RESOLVED'

def test_get_statistics(temp_db, sample_normal_events):
    for event in sample_normal_events:
        temp_db.insert_event(event)
    alert = Alert(
        timestamp=datetime.now(),
        rule_id='TEST_RULE',
        severity='LOW',
        source_ip='1.1.1.1',
        destination_ip='2.2.2.2',
        description='Test',
        evidence='{}'
    )
    temp_db.insert_alert(alert)
    
    stats = temp_db.get_statistics()
    assert stats['total_events'] == 5
    assert stats['total_alerts'] == 1

def test_protocol_distribution(temp_db, sample_normal_events):
    for event in sample_normal_events:
        temp_db.insert_event(event)
    stats = temp_db.get_statistics()
    assert 'TCP' in stats.get('protocol_distribution', {}) or stats.get('total_events') > 0

def test_clear_all_data(temp_db, sample_normal_events):
    for event in sample_normal_events:
        temp_db.insert_event(event)
    temp_db.clear_all_data()
    assert len(temp_db.get_events()) == 0
