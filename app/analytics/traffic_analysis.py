import pandas as pd
from typing import Dict, Any

def get_traffic_summary(repository) -> Dict[str, Any]:
    events = repository.get_events(limit=1)
    return {
        "total_events": repository.get_event_count(),
        "protocol_breakdown": repository.get_protocol_distribution(),
        "time_range": "N/A" # Simplified for now
    }

def get_traffic_over_time(repository, interval='hour') -> pd.DataFrame:
    data = repository.get_events_over_time(interval)
    return pd.DataFrame(data) if data else pd.DataFrame(columns=['timestamp', 'count'])

def get_protocol_breakdown(repository) -> pd.DataFrame:
    data = repository.get_protocol_distribution()
    return pd.DataFrame(data) if data else pd.DataFrame(columns=['protocol', 'count'])

def get_top_sources(repository, limit=10) -> pd.DataFrame:
    data = repository.get_top_source_ips(limit)
    return pd.DataFrame(data) if data else pd.DataFrame(columns=['source_ip', 'count'])

def get_top_destinations(repository, limit=10) -> pd.DataFrame:
    # Requires custom query if we want destinations specifically
    # For now returning empty df to satisfy signature, or just mock it
    return pd.DataFrame(columns=['destination_ip', 'count'])

def get_top_dest_ports(repository, limit=10) -> pd.DataFrame:
    data = repository.get_top_destination_ports(limit)
    return pd.DataFrame(data) if data else pd.DataFrame(columns=['destination_port', 'count'])

def get_connection_frequency(repository) -> pd.DataFrame:
    # Mocks for now
    return pd.DataFrame(columns=['source_ip', 'destination_ip', 'count'])
