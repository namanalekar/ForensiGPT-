import uuid
import json
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status, Request
from app.models.db_models import get_db
from app.models.pydantic_models import (
    FileUploadResponse,
    FileResponse,
    UnverifiedModalData,
    RiskFactor
)
from app.core.config import settings
from app.core.security import sanitize_filename, calculate_hashes, strip_execute_permissions
from app.core.rate_limit import rate_limiter
from app.analyzers.filetype import FileTypeInspector

router = APIRouter(prefix="/cases", tags=["upload"])

@router.post("/{case_id}/upload", response_model=FileUploadResponse)
async def upload_files(
    case_id: str,
    request: Request,
    files: list[UploadFile] = File(...)
):
    # Enforce rate limiting
    rate_limiter.check(request)

    with get_db() as db:
        # Check case exists
        c_cur = db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
        if not c_cur.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

        uploaded_results: list[FileResponse] = []
        popups_required: list[UnverifiedModalData] = []

        for upload in files:
            file_id = str(uuid.uuid4())
            sanitized_name = sanitize_filename(upload.filename or "uploaded_file.bin")
            dest_filename = f"{file_id}_{sanitized_name}"
            dest_path = settings.UPLOAD_DIR / dest_filename

            # Stream save with size check
            total_bytes = 0
            with open(dest_path, "wb") as buffer:
                while chunk := await upload.read(65536):
                    total_bytes += len(chunk)
                    if total_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
                        buffer.close()
                        dest_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"File '{sanitized_name}' exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
                        )
                    buffer.write(chunk)

            # Strip execute permissions
            strip_execute_permissions(dest_path)

            # Calculate cryptographic hashes
            hashes = calculate_hashes(dest_path)

            # Deterministic file type & unverified inspection
            inspection = FileTypeInspector.inspect(dest_path, sanitized_name)
            now_iso = datetime.now(timezone.utc).isoformat()

            # Save file record in SQLite
            db.execute(
                """
                INSERT INTO files (
                    id, case_id, original_filename, stored_filename, file_path,
                    file_size, sha256, sha1, md5, mime_type, detected_category,
                    true_file_type, extension_match, has_trailing_data, trailing_bytes_count,
                    unverified_flags, verdict, risk_score, risk_breakdown, uploaded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    case_id,
                    sanitized_name,
                    dest_filename,
                    str(dest_path),
                    total_bytes,
                    hashes["sha256"],
                    hashes["sha1"],
                    hashes["md5"],
                    inspection["mime_type"],
                    inspection["detected_category"],
                    inspection["true_file_type"],
                    1 if inspection["extension_match"] else 0,
                    1 if inspection["has_trailing_data"] else 0,
                    inspection["trailing_bytes_count"],
                    json.dumps(inspection["unverified_flags"]),
                    inspection["verdict"],
                    inspection["risk_score"],
                    json.dumps([r.model_dump() for r in inspection["risk_breakdown"]]),
                    now_iso
                )
            )

            file_resp = FileResponse(
                id=file_id,
                case_id=case_id,
                original_filename=sanitized_name,
                file_size=total_bytes,
                sha256=hashes["sha256"],
                sha1=hashes["sha1"],
                md5=hashes["md5"],
                mime_type=inspection["mime_type"],
                detected_category=inspection["detected_category"],
                true_file_type=inspection["true_file_type"],
                extension_match=inspection["extension_match"],
                has_trailing_data=inspection["has_trailing_data"],
                trailing_bytes_count=inspection["trailing_bytes_count"],
                unverified_flags=inspection["unverified_flags"],
                verdict=inspection["verdict"],
                risk_score=inspection["risk_score"],
                risk_breakdown=inspection["risk_breakdown"],
                uploaded_at=now_iso,
                unverified_popup=inspection["unverified_popup"]
            )

            uploaded_results.append(file_resp)
            if inspection["unverified_popup"]:
                popups_required.append(inspection["unverified_popup"])

        db.commit()

        return FileUploadResponse(
            case_id=case_id,
            uploaded_files=uploaded_results,
            popup_required_files=popups_required
        )

@router.delete("/{case_id}/files/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(case_id: str, file_id: str):
    """
    Deletes an individual file from disk and database (e.g., when user clicks 'Cancel and delete file' in the unverified popup).
    """
    with get_db() as db:
        cursor = db.execute("SELECT file_path FROM files WHERE id = ? AND case_id = ?", (file_id, case_id))
        row = cursor.fetchone()
        if row and row["file_path"]:
            p = Path(row["file_path"])
            if p.exists():
                p.unlink(missing_ok=True)
        db.execute("DELETE FROM files WHERE id = ? AND case_id = ?", (file_id, case_id))
        db.commit()
    return None
