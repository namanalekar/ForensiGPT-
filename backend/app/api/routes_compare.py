from pathlib import Path
from fastapi import APIRouter, HTTPException, status
from app.models.db_models import get_db
from app.analyzers.filetype import FileTypeInspector
from app.analyzers.entropy import calculate_shannon_entropy

router = APIRouter(prefix="/cases", tags=["compare"])

@router.get("/{case_id}/compare")
def compare_files(case_id: str, file_a_id: str, file_b_id: str):
    with get_db() as db:
        cur_a = db.execute("SELECT * FROM files WHERE id = ? AND case_id = ?", (file_a_id, case_id))
        row_a = cur_a.fetchone()
        cur_b = db.execute("SELECT * FROM files WHERE id = ? AND case_id = ?", (file_b_id, case_id))
        row_b = cur_b.fetchone()

        if not row_a or not row_b:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both files not found")

        path_a = Path(row_a["file_path"])
        path_b = Path(row_b["file_path"])

        ent_a = calculate_shannon_entropy(path_a.read_bytes()) if path_a.exists() else 0.0
        ent_b = calculate_shannon_entropy(path_b.read_bytes()) if path_b.exists() else 0.0

        diffs = {
            "hashes": {
                "sha256_match": row_a["sha256"] == row_b["sha256"],
                "file_a": {"sha256": row_a["sha256"], "md5": row_a["md5"]},
                "file_b": {"sha256": row_b["sha256"], "md5": row_b["md5"]}
            },
            "size": {
                "file_a_bytes": row_a["file_size"],
                "file_b_bytes": row_b["file_size"],
                "delta_bytes": row_a["file_size"] - row_b["file_size"]
            },
            "format": {
                "file_a_true": row_a["true_file_type"],
                "file_b_true": row_b["true_file_type"],
                "format_match": row_a["true_file_type"] == row_b["true_file_type"]
            },
            "entropy": {
                "file_a_entropy": ent_a,
                "file_b_entropy": ent_b,
                "delta_entropy": round(abs(ent_a - ent_b), 4)
            },
            "risk": {
                "file_a_verdict": row_a["verdict"],
                "file_a_score": row_a["risk_score"],
                "file_b_verdict": row_b["verdict"],
                "file_b_score": row_b["risk_score"]
            }
        }

        return {
            "case_id": case_id,
            "file_a": row_a["original_filename"],
            "file_b": row_b["original_filename"],
            "comparison": diffs
        }
