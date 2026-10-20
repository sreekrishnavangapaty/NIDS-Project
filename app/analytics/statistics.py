def get_dashboard_stats(repository) -> dict:
    return repository.get_statistics()

def get_alert_statistics(repository) -> dict:
    return {
        "by_severity": repository.get_alerts_by_severity(),
        "over_time": repository.get_alerts_over_time()
    }

def get_detection_statistics(repository) -> dict:
    return {
        "by_rule": repository.get_alerts_by_rule()
    }
