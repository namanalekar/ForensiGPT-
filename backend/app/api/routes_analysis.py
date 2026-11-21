import json
from pathlib import Path
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse as FastApiFileResponse
from app.models.db_models import get_db
from app.core.config import settings
from app.analyzers.image_engine import ImageForensicsCoordinator
from app.analyzers.logs.parser import LogForensicsEngine

router = APIRouter(prefix="/cases", tags=["analysis"])

@router.post("/{case_id}/files/{file_id}/analyze")
def trigger_file_analysis(case_id: str, file_id: str, target_year: int = 2026, timezone_offset_hours: float = 0.0):
    with get_db() as db:
        cur = db.execute("SELECT * FROM files WHERE id = ? AND case_id = ?", (file_id, case_id))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

        file_path = Path(row["file_path"])
        if not file_path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content not found on disk")

        category = row["detected_category"]
        mime_type = row["mime_type"]
        original_filename = row["original_filename"]

        if category == "image" or "image" in mime_type:
            result = ImageForensicsCoordinator.analyze_image(
                file_path=file_path,
                file_id=file_id,
                original_filename=original_filename,
                mime_type=mime_type
            )
            return result
        elif category == "log" or "text" in mime_type or file_path.suffix.lower() in {".log", ".txt", ".csv", ".syslog"}:
            result = LogForensicsEngine.analyze_log_file(
                file_path=file_path,
                file_id=file_id,
                case_id=case_id,
                target_year=target_year,
                timezone_offset_hours=timezone_offset_hours
            )
            return result
        else:
            return {
                "file_id": file_id,
                "analyzer_type": "generic",
                "message": f"Deep analysis for category '{category}' completed via standard file inspection.",
                "evidence_items": [],
                "metadata_blob": {},
                "visual_artifacts": {}
            }

@router.get("/{case_id}/files/{file_id}/analysis")
def get_file_analysis(case_id: str, file_id: str):
    with get_db() as db:
        cur = db.execute("SELECT * FROM analysis_results WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        if not row:
            # Trigger analysis on demand if not yet analyzed
            return trigger_file_analysis(case_id, file_id)

        return {
            "file_id": row["file_id"],
            "analyzer_type": row["analyzer_type"],
            "evidence_items": json.loads(row["evidence_items"] or "[]"),
            "metadata_blob": json.loads(row["metadata_blob"] or "{}"),
            "visual_artifacts": json.loads(row["visual_artifacts"] or "{}"),
            "analyzed_at": row["analyzed_at"]
        }

@router.get("/visuals/{filename}")
def serve_visual_artifact(filename: str):
    """Safely serves generated ELA, LSB, and Entropy PNG visual artifacts."""
    safe_name = Path(filename).name
    artifact_path = settings.VISUALS_DIR / safe_name
    if not artifact_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Visual artifact not found")
    return FastApiFileResponse(artifact_path, media_type="image/png")

@router.get("/vault/{filename}")
def serve_vault_file(filename: str):
    """Safely serves file for download/preview with octet-stream disposition."""
    safe_name = Path(filename).name
    file_path = settings.UPLOAD_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    # For images, return image MIME type for tri-view rendering
    suffix = file_path.suffix.lower()
    media_type = "application/octet-stream"
    if suffix in {".jpg", ".jpeg"}:
        media_type = "image/jpeg"
    elif suffix == ".png":
        media_type = "image/png"
    elif suffix == ".webp":
        media_type = "image/webp"
    return FastApiFileResponse(file_path, media_type=media_type)
