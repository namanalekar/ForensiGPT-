import sqlite3
import json
from pathlib import Path
from contextlib import contextmanager
from typing import Generator
from app.core.config import settings

CREATE_TABLES_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    metadata_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    detected_category TEXT NOT NULL,
    true_file_type TEXT NOT NULL,
    extension_match INTEGER NOT NULL,
    has_trailing_data INTEGER NOT NULL DEFAULT 0,
    trailing_bytes_count INTEGER NOT NULL DEFAULT 0,
    unverified_flags TEXT DEFAULT '[]',
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_breakdown TEXT DEFAULT '[]',
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    analyzer_type TEXT NOT NULL,
    evidence_items TEXT NOT NULL DEFAULT '[]',
    metadata_blob TEXT NOT NULL DEFAULT '{}',
    visual_artifacts TEXT NOT NULL DEFAULT '{}',
    analyzed_at TEXT NOT NULL,
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS log_events (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    timestamp_epoch REAL,
    host TEXT DEFAULT '',
    process TEXT DEFAULT '',
    message TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    raw_line TEXT NOT NULL,
    normalized_type TEXT NOT NULL,
    relevance_score INTEGER DEFAULT 0,
    iocs TEXT DEFAULT '[]',
    mitre_tags TEXT DEFAULT '[]',
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS correlation_timelines (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    anchor_file_id TEXT NOT NULL,
    anchor_timestamp TEXT NOT NULL,
    anchor_type TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    manual_offset_seconds INTEGER NOT NULL DEFAULT 0,
    correlation_items TEXT NOT NULL DEFAULT '[]',
    clock_skew_warning TEXT,
    narrative_report TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    explanation_mode TEXT NOT NULL DEFAULT 'analyst',
    risk_score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    structured_json TEXT NOT NULL,
    markdown_content TEXT NOT NULL,
    privacy_mode_active INTEGER NOT NULL DEFAULT 0,
    model_used TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_history (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    evidence_citations TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
"""

def get_db_connection() -> sqlite3.Connection:
    """Helper to establish a connection with Row factory."""
    conn = sqlite3.connect(str(settings.DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

def init_db() -> None:
    """Initializes SQLite database and tables."""
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.executescript(CREATE_TABLES_SQL)
        db.commit()
