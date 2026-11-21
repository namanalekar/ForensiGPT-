import uuid
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from app.models.db_models import get_db
from app.models.pydantic_models import GroundedChatRequest, GroundedChatResponse
from app.ai.gemini_client import GeminiForensicsClient

router = APIRouter(prefix="/cases", tags=["chat"])

@router.post("/{case_id}/chat", response_model=GroundedChatResponse)
def ask_the_evidence(case_id: str, req: GroundedChatRequest):
    # Collect case evidence context
    with get_db() as db:
        # Check case
        c_cur = db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
        if not c_cur.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

        # Files
        f_cur = db.execute("SELECT original_filename, sha256, true_file_type, verdict, risk_score FROM files WHERE case_id = ?", (case_id,))
        files = [dict(r) for r in f_cur.fetchall()]

        # Analysis findings
        a_cur = db.execute(
            """
            SELECT a.evidence_items, f.original_filename FROM analysis_results a
            JOIN files f ON a.file_id = f.id
            WHERE f.case_id = ?
            """,
            (case_id,)
        )
        evidence_items = []
        for r in a_cur.fetchall():
            items = json.loads(r["evidence_items"] or "[]")
            for item in items:
                item["source_file"] = r["original_filename"]
                evidence_items.append(item)

        # Log events
        l_cur = db.execute("SELECT timestamp, process, message, relevance_score, iocs FROM log_events WHERE case_id = ? ORDER BY relevance_score DESC LIMIT 30", (case_id,))
        top_logs = [dict(r) for r in l_cur.fetchall()]

        # Fetch chat history
        h_cur = db.execute("SELECT role, content FROM chat_history WHERE case_id = ? ORDER BY created_at ASC", (case_id,))
        history = [dict(r) for r in h_cur.fetchall()]

    evidence_context = {
        "files_analyzed": files,
        "evidence_items": evidence_items,
        "notable_log_events": top_logs
    }

    answer_text, citations = GeminiForensicsClient.ask_the_evidence(
        evidence_context=evidence_context,
        user_question=req.message,
        conversation_history=history
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    msg_id = str(uuid.uuid4())

    # Save to chat history
    with get_db() as db:
        # Save user message
        db.execute(
            "INSERT INTO chat_history (id, case_id, role, content, evidence_citations, created_at) VALUES (?, ?, 'user', ?, '[]', ?)",
            (str(uuid.uuid4()), case_id, req.message, now_iso)
        )
        # Save assistant message
        db.execute(
            "INSERT INTO chat_history (id, case_id, role, content, evidence_citations, created_at) VALUES (?, ?, 'assistant', ?, ?, ?)",
            (msg_id, case_id, answer_text, json.dumps(citations), now_iso)
        )
        db.commit()

    return GroundedChatResponse(
        case_id=case_id,
        role="assistant",
        content=answer_text,
        evidence_citations=citations,
        created_at=now_iso
    )

@router.get("/{case_id}/chat")
def get_chat_history(case_id: str):
    with get_db() as db:
        cur = db.execute("SELECT role, content, evidence_citations, created_at FROM chat_history WHERE case_id = ? ORDER BY created_at ASC", (case_id,))
        rows = cur.fetchall()

    messages = []
    for r in rows:
        messages.append({
            "role": r["role"],
            "content": r["content"],
            "evidence_citations": json.loads(r["evidence_citations"] or "[]"),
            "created_at": r["created_at"]
        })
    return {"case_id": case_id, "messages": messages}
