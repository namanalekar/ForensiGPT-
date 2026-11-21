import uuid
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from app.models.db_models import get_db
from app.models.pydantic_models import CaseCreate, CaseResponse, FileResponse
from app.core.config import settings

router = APIRouter(prefix="/cases", tags=["cases"])

@router.post("", response_model=CaseResponse)
def create_case(case_in: CaseCreate):
    case_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            """
            INSERT INTO cases (id, title, description, created_at, updated_at, status)
            VALUES (?, ?, ?, ?, ?, 'open')
            """,
            (case_id, case_in.title, case_in.description, now, now)
        )
        db.commit()

    return CaseResponse(
        id=case_id,
        title=case_in.title,
        description=case_in.description,
        created_at=now,
        updated_at=now,
        status="open",
        files=[]
    )

@router.get("", response_model=list[CaseResponse])
def list_cases():
    with get_db() as db:
        cursor = db.execute("SELECT id, title, description, created_at, updated_at, status FROM cases ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cases = []
        for row in rows:
            cases.append(CaseResponse(
                id=row["id"],
                title=row["title"],
                description=row["description"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                status=row["status"],
                files=[]
            ))
        return cases

@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str):
    with get_db() as db:
        cursor = db.execute("SELECT id, title, description, created_at, updated_at, status FROM cases WHERE id = ?", (case_id,))
        case_row = cursor.fetchone()
        if not case_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

        # Fetch files for this case
        f_cursor = db.execute("SELECT * FROM files WHERE case_id = ? ORDER BY uploaded_at ASC", (case_id,))
        file_rows = f_cursor.fetchall()

        files = []
        for f in file_rows:
            unverified_flags = json.loads(f["unverified_flags"] or "[]")
            risk_breakdown = json.loads(f["risk_breakdown"] or "[]")
            files.append(FileResponse(
                id=f["id"],
                case_id=f["case_id"],
                original_filename=f["original_filename"],
                file_size=f["file_size"],
                sha256=f["sha256"],
                sha1=f["sha1"],
                md5=f["md5"],
                mime_type=f["mime_type"],
                detected_category=f["detected_category"],
                true_file_type=f["true_file_type"],
                extension_match=bool(f["extension_match"]),
                has_trailing_data=bool(f["has_trailing_data"]),
                trailing_bytes_count=f["trailing_bytes_count"],
                unverified_flags=unverified_flags,
                verdict=f["verdict"],
                risk_score=f["risk_score"],
                risk_breakdown=risk_breakdown,
                uploaded_at=f["uploaded_at"]
            ))

        return CaseResponse(
            id=case_row["id"],
            title=case_row["title"],
            description=case_row["description"],
            created_at=case_row["created_at"],
            updated_at=case_row["updated_at"],
            status=case_row["status"],
            files=files
        )

@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case(case_id: str):
    with get_db() as db:
        # Get files to remove from disk
        cursor = db.execute("SELECT file_path FROM files WHERE case_id = ?", (case_id,))
        rows = cursor.fetchall()
        for row in rows:
            p = row["file_path"]
            if p:
                try:
                    import os
                    if os.path.exists(p):
                        os.remove(p)
                except Exception:
                    pass

        db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        db.commit()
    return None
