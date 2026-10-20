"""Database connection helpers.

The ``DatabaseRepository`` now manages its own connection, so these helpers
are kept for backward compatibility and for the FastAPI lifespan hook.
"""
import sqlite3
from pathlib import Path
from app.config import config
import logging

logger = logging.getLogger(__name__)


def get_db_path() -> Path:
    db_path = Path(config.DATABASE_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(get_db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_db_connection():
    """Alias used by some modules."""
    return get_connection()


def init_db():
    """Ensure tables exist.  The repository constructor already creates
    tables, so this simply instantiates one to trigger that logic."""
    from app.database.repository import DatabaseRepository
    repo = DatabaseRepository()
    repo.close()
    logger.info("Database initialized.")
