from pathlib import Path
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, status
from app.models.db_models import get_db
from app.correlation.anchors import AnchorExtractor
from app.correlation.sync_engine import ImageLogSyncEngine

router = APIRouter(prefix="/cases", tags=["correlation"])

class SyncRequest(BaseModel):
    anchor_file_id: str
    anchor_type: str
    anchor_epoch: float
    anchor_label: str = "Anchor Timestamp"
    window_seconds: int = Field(default=300, ge=30, le=7200)
    manual_offset_seconds: int = 0

@router.get("/{case_id}/correlation/anchors")
def get_case_anchors(case_id: str, timezone_offset_hours: float = 0.0):
    with get_db() as db:
        cur = db.execute("SELECT id, original_filename, file_path, uploaded_at, detected_category FROM files WHERE case_id = ?", (case_id,))
        files = cur.fetchall()

    case_anchors = []
    for f in files:
        file_path = Path(f["file_path"])
        anchors = AnchorExtractor.get_anchors_for_file(
            file_path=file_path,
            file_id=f["id"],
            original_filename=f["original_filename"],
            uploaded_at=f["uploaded_at"],
            user_timezone_offset_hours=timezone_offset_hours
        )
        case_anchors.append({
            "file_id": f["id"],
            "filename": f["original_filename"],
            "category": f["detected_category"],
            "anchors": anchors
        })

    return {"case_id": case_id, "files": case_anchors}

@router.post("/{case_id}/correlation/sync")
def run_correlation_sync(case_id: str, req: SyncRequest):
    result = ImageLogSyncEngine.correlate(
        case_id=case_id,
        anchor_file_id=req.anchor_file_id,
        anchor_epoch=req.anchor_epoch,
        anchor_type=req.anchor_type,
        anchor_label=req.anchor_label,
        window_seconds=req.window_seconds,
        manual_offset_seconds=req.manual_offset_seconds
    )
    return result
