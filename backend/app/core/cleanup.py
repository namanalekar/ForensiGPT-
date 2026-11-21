import asyncio
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from app.core.config import settings
from app.models.db_models import get_db

def perform_retention_cleanup() -> int:
    """
    Deletes files and cases that are older than RETENTION_HOURS (default 24h).
    Returns count of cleaned files.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.RETENTION_HOURS)
    cutoff_iso = cutoff.isoformat()

    cleaned_count = 0
    with get_db() as db:
        # Find old files
        cursor = db.execute("SELECT id, file_path FROM files WHERE uploaded_at < ?", (cutoff_iso,))
        rows = cursor.fetchall()
        for row in rows:
            path_str = row["file_path"]
            if path_str:
                p = Path(path_str)
                if p.exists():
                    try:
                        p.unlink(missing_ok=True)
                        cleaned_count += 1
                    except Exception:
                        pass
        db.execute("DELETE FROM files WHERE uploaded_at < ?", (cutoff_iso,))

        # Find empty or old cases
        db.execute("DELETE FROM cases WHERE created_at < ?", (cutoff_iso,))
        db.commit()

    return cleaned_count

async def retention_worker(interval_seconds: int = 3600):
    """Background task running every hour to prune expired cases and files."""
    while True:
        try:
            perform_retention_cleanup()
        except Exception:
            pass
        await asyncio.sleep(interval_seconds)
