import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from app.models.db_models import get_db
from app.models.pydantic_models import (
    ReportGenerateRequest,
    RedactionItem,
    RedactionPreviewPayload
)
from app.ai.gemini_client import GeminiForensicsClient
from app.ai.injection_guard import PromptInjectionGuard

router = APIRouter(prefix="/cases", tags=["reports"])

def _gather_case_evidence(case_id: str) -> tuple[str, list[dict], dict, dict | None, int, str]:
    with get_db() as db:
        c_cur = db.execute("SELECT title FROM cases WHERE id = ?", (case_id,))
        case_row = c_cur.fetchone()
        if not case_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        case_title = case_row["title"]

        # Files
        f_cur = db.execute("SELECT * FROM files WHERE case_id = ?", (case_id,))
        files = [dict(r) for r in f_cur.fetchall()]

        # Analyses
        a_cur = db.execute(
            """
            SELECT a.* FROM analysis_results a
            JOIN files f ON a.file_id = f.id
            WHERE f.case_id = ?
            """,
            (case_id,)
        )
        analyses = {r["file_id"]: {
            "evidence_items": json.loads(r["evidence_items"] or "[]"),
            "metadata_blob": json.loads(r["metadata_blob"] or "{}")
        } for r in a_cur.fetchall()}

        # Correlation timeline
        t_cur = db.execute("SELECT * FROM correlation_timelines WHERE case_id = ? ORDER BY created_at DESC LIMIT 1", (case_id,))
        t_row = t_cur.fetchone()
        sync_result = None
        if t_row:
            sync_result = {
                "window_seconds": t_row["window_seconds"],
                "correlated_events": json.loads(t_row["correlation_items"] or "[]"),
                "clock_skew_warning": t_row["clock_skew_warning"]
            }

        # Calculate max risk score & verdict
        risk_score = max([f["risk_score"] for f in files], default=0)
        # Priority: Likely Malicious > Suspicious > Unverified > Verified-Clean-Looking
        verdicts = [f["verdict"] for f in files]
        if "Likely Malicious" in verdicts:
            verdict = "Likely Malicious"
        elif "Suspicious" in verdicts:
            verdict = "Suspicious"
        elif "Unverified" in verdicts:
            verdict = "Unverified"
        else:
            verdict = "Verified-Clean-Looking"

    return case_title, files, analyses, sync_result, risk_score, verdict

@router.post("/{case_id}/reports/preview-redaction", response_model=RedactionPreviewPayload)
def preview_redactions(case_id: str):
    case_title, files, analyses, sync_result, risk_score, verdict = _gather_case_evidence(case_id)
    raw_payload = {
        "case_title": case_title,
        "files": files,
        "analyses": analyses,
        "sync_result": sync_result
    }

    # Find candidates for redaction (GPS, IPs)
    candidates = []
    # Check GPS in analyses
    for fid, a in analyses.items():
        exif = a.get("metadata_blob", {}).get("exif", {})
        if exif.get("gps_latitude"):
            candidates.append(RedactionItem(
                field_name=f"files[{fid}].exif.gps_latitude",
                original_value=str(exif["gps_latitude"]),
                redacted_value="[REDACTED_GPS_LAT]",
                category="GPS"
            ))
        if exif.get("gps_longitude"):
            candidates.append(RedactionItem(
                field_name=f"files[{fid}].exif.gps_longitude",
                original_value=str(exif["gps_longitude"]),
                redacted_value="[REDACTED_GPS_LON]",
                category="GPS"
            ))

    # Anti-prompt injection pre-flight check
    sanitized_payload, injection_evidence = PromptInjectionGuard.scan_evidence_package(raw_payload)

    return RedactionPreviewPayload(
        case_id=case_id,
        redaction_candidates=candidates,
        sanitized_evidence_json=sanitized_payload
    )

@router.post("/{case_id}/reports/generate")
def generate_report(case_id: str, req: ReportGenerateRequest):
    case_title, files, analyses, sync_result, risk_score, verdict = _gather_case_evidence(case_id)

    # 1. Anti-Prompt-Injection Scanner
    raw_evidence = {
        "files": files,
        "analyses": analyses,
        "sync_result": sync_result
    }
    sanitized_evidence, injection_evidence = PromptInjectionGuard.scan_evidence_package(raw_evidence)

    # If prompt injection detected, elevate risk score and verdict!
    if injection_evidence:
        risk_score = min(risk_score + 30, 100)
        verdict = "Likely Malicious"
        # Append injection evidence
        for f in sanitized_evidence["files"]:
            fid = f["id"]
            if fid in sanitized_evidence["analyses"]:
                sanitized_evidence["analyses"][fid]["evidence_items"].extend([e.model_dump() for e in injection_evidence])
                break

    # 2. Generate report via Gemini Client or Offline Template
    report_schema, model_used = GeminiForensicsClient.generate_report(
        case_title=case_title,
        files=sanitized_evidence["files"],
        analysis_map=sanitized_evidence["analyses"],
        sync_result=sanitized_evidence["sync_result"],
        risk_score=risk_score,
        verdict=verdict,
        mode=req.explanation_mode,
        privacy_mode=req.privacy_mode
    )

    report_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    report_json_str = report_schema.model_dump_json(indent=2)

    # Save to SQLite reports table
    with get_db() as db:
        db.execute(
            """
            INSERT INTO reports (
                id, case_id, explanation_mode, risk_score, verdict,
                structured_json, markdown_content, privacy_mode_active, model_used, generated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                case_id,
                req.explanation_mode,
                report_schema.risk_score,
                report_schema.verdict,
                report_json_str,
                report_schema.executive_summary,
                1 if req.privacy_mode else 0,
                model_used,
                now_iso
            )
        )
        db.commit()

    return {
        "report_id": report_id,
        "case_id": case_id,
        "explanation_mode": req.explanation_mode,
        "model_used": model_used,
        "privacy_mode_active": req.privacy_mode,
        "generated_at": now_iso,
        "report": report_schema.model_dump()
    }

from fastapi.responses import FileResponse as FastApiFileResponse, PlainTextResponse, Response
from app.reports.pdf_export import PDFReportExporter
from app.reports.md_export import MarkdownReportExporter, CSVTimelineExporter
from app.core.config import settings
from pathlib import Path

@router.get("/{case_id}/reports/latest")
def get_latest_report(case_id: str):
    with get_db() as db:
        cur = db.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY generated_at DESC LIMIT 1", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No reports generated yet for this case.")

        return {
            "report_id": row["id"],
            "case_id": row["case_id"],
            "explanation_mode": row["explanation_mode"],
            "model_used": row["model_used"],
            "privacy_mode_active": bool(row["privacy_mode_active"]),
            "generated_at": row["generated_at"],
            "report": json.loads(row["structured_json"])
        }

@router.get("/{case_id}/reports/export/pdf")
def export_report_pdf(case_id: str):
    case_title, files, analyses, sync_result, risk_score, verdict = _gather_case_evidence(case_id)
    with get_db() as db:
        cur = db.execute("SELECT structured_json FROM reports WHERE case_id = ? ORDER BY generated_at DESC LIMIT 1", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No report generated yet to export.")
        report_data = json.loads(row["structured_json"])

    dest_file = settings.REPORT_DIR / f"{case_id}_forensic_report.pdf"
    PDFReportExporter.export_pdf(case_title, report_data, files, dest_file)
    return FastApiFileResponse(
        dest_file,
        media_type="application/pdf",
        filename=f"ForensiGPT_{case_title.replace(' ', '_')}_Report.pdf"
    )

@router.get("/{case_id}/reports/export/markdown")
def export_report_markdown(case_id: str):
    case_title, files, analyses, sync_result, risk_score, verdict = _gather_case_evidence(case_id)
    with get_db() as db:
        cur = db.execute("SELECT structured_json FROM reports WHERE case_id = ? ORDER BY generated_at DESC LIMIT 1", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No report generated yet to export.")
        report_data = json.loads(row["structured_json"])

    md_text = MarkdownReportExporter.export_markdown(case_title, report_data, files)
    return PlainTextResponse(
        content=md_text,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="ForensiGPT_{case_title.replace(" ", "_")}.md"'}
    )

@router.get("/{case_id}/reports/export/json")
def export_report_json(case_id: str):
    case_title, files, analyses, sync_result, risk_score, verdict = _gather_case_evidence(case_id)
    with get_db() as db:
        cur = db.execute("SELECT structured_json FROM reports WHERE case_id = ? ORDER BY generated_at DESC LIMIT 1", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No report generated yet to export.")
        report_data = json.loads(row["structured_json"])

    full_package = {
        "case_id": case_id,
        "case_title": case_title,
        "chain_of_custody_files": files,
        "deep_analyses": analyses,
        "correlation_timeline": sync_result,
        "ai_report": report_data
    }
    return Response(
        content=json.dumps(full_package, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="ForensiGPT_{case_id}_Package.json"'}
    )

@router.get("/{case_id}/reports/export/csv")
def export_timeline_csv(case_id: str):
    with get_db() as db:
        cur = db.execute("SELECT * FROM log_events WHERE case_id = ? ORDER BY timestamp_epoch ASC", (case_id,))
        rows = [dict(r) for r in cur.fetchall()]

    csv_text = CSVTimelineExporter.export_csv(rows)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="ForensiGPT_{case_id}_Timeline.csv"'}
    )
