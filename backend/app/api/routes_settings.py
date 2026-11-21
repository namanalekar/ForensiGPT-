import shutil
from fastapi import APIRouter, status
from app.models.pydantic_models import SettingsDTO
from app.core.config import settings
from app.models.db_models import get_db

router = APIRouter(prefix="/settings", tags=["settings"])

@router.get("", response_model=SettingsDTO)
def get_settings():
    return SettingsDTO(
        gemini_model=settings.GEMINI_MODEL,
        gemini_api_key_set=bool(settings.GEMINI_API_KEY.strip()),
        privacy_mode_default=settings.PRIVACY_MODE_DEFAULT,
        retention_hours=settings.RETENTION_HOURS,
        max_upload_size_mb=settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024),
        virustotal_configured=bool(settings.VIRUSTOTAL_API_KEY.strip())
    )

@router.post("/purge", status_code=status.HTTP_200_OK)
def purge_all_data():
    """
    Immediate 'Delete my data now' button handler.
    Cleans all uploaded files, generated reports, and resets the SQLite database.
    """
    with get_db() as db:
        db.execute("DELETE FROM chat_history;")
        db.execute("DELETE FROM reports;")
        db.execute("DELETE FROM correlation_timelines;")
        db.execute("DELETE FROM log_events;")
        db.execute("DELETE FROM analysis_results;")
        db.execute("DELETE FROM files;")
        db.execute("DELETE FROM cases;")
        db.commit()

    # Clean disk directories
    for folder in [settings.UPLOAD_DIR, settings.REPORT_DIR]:
        if folder.exists():
            for item in folder.iterdir():
                try:
                    if item.is_file():
                        item.unlink(missing_ok=True)
                    elif item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                except Exception:
                    pass

    return {"status": "success", "message": "All cases, uploaded files, and generated forensic reports have been permanently deleted."}
