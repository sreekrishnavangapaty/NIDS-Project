from app.config import config

def get_port_scan_threshold() -> int:
    return config.PORT_SCAN_THRESHOLD

def get_port_scan_window() -> int:
    return config.PORT_SCAN_WINDOW

def get_repeated_connection_threshold() -> int:
    return config.REPEATED_CONNECTION_THRESHOLD

def get_repeated_connection_window() -> int:
    return config.REPEATED_CONNECTION_WINDOW

def get_high_rate_threshold() -> int:
    return config.HIGH_RATE_THRESHOLD

def get_high_rate_window() -> int:
    return config.HIGH_RATE_WINDOW

def get_all_thresholds() -> dict:
    return {
        "PORT_SCAN_THRESHOLD": get_port_scan_threshold(),
        "PORT_SCAN_WINDOW": get_port_scan_window(),
        "REPEATED_CONNECTION_THRESHOLD": get_repeated_connection_threshold(),
        "REPEATED_CONNECTION_WINDOW": get_repeated_connection_window(),
        "HIGH_RATE_THRESHOLD": get_high_rate_threshold(),
        "HIGH_RATE_WINDOW": get_high_rate_window()
    }
