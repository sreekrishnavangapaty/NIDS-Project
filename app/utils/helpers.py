from datetime import datetime
import uuid

def format_timestamp(dt: datetime) -> str:
    return dt.isoformat()

def parse_timestamp(s: str) -> datetime:
    return datetime.fromisoformat(s)

def safe_int(val, default=0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def truncate_string(s: str, max_len: int = 100) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s[:max_len] + '...' if len(s) > max_len else s

def generate_id() -> str:
    return str(uuid.uuid4())
