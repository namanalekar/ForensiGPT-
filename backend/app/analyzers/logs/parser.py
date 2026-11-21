import json
import uuid
from pathlib import Path
from typing import Any
from app.models.db_models import get_db
from app.analyzers.ioc import IOCExtractor
from app.analyzers.mitre import MitreMapper
from app.analyzers.logs.auth_log import AuthLogParser
from app.analyzers.logs.syslog import SyslogParser
from app.analyzers.logs.web_log import WebLogParser

class LogForensicsEngine:
    """
    Unified Log Forensics Engine.
    Orchestrates parsing of auth.log, syslog, and web access logs,
    resolves timezone/year ambiguities, extracts IOCs, and maps to MITRE ATT&CK.
    """

    @classmethod
    def analyze_log_file(
        cls,
        file_path: Path,
        file_id: str,
        case_id: str,
        target_year: int = 2026,
        timezone_offset_hours: float = 0.0
    ) -> dict[str, Any]:
        text_content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = [line for line in text_content.splitlines() if line.strip()]

        # Format auto-detection
        sample = "\n".join(lines[:20])
        detected_format = "syslog"
        if "sshd[" in sample or "sudo:" in sample or "Failed password" in sample or "Accepted password" in sample:
            detected_format = "auth_log"
        elif any(verb in sample for verb in ['"GET ', '"POST ', '"HEAD ', '"PUT ']):
            detected_format = "web_log"

        assumptions = []
        if detected_format in {"auth_log", "syslog"}:
            assumptions.append(
                f"Assumed target year: {target_year} (Syslog RFC 3164 standard does not record the calendar year)."
            )
            if timezone_offset_hours == 0.0:
                assumptions.append("Assumed timezone: UTC+00:00 (user offset override not specified).")
            else:
                sign = "+" if timezone_offset_hours >= 0 else "-"
                assumptions.append(f"Applied timezone offset: UTC{sign}{abs(timezone_offset_hours):.1f}h.")

        # Parse based on format
        if detected_format == "auth_log":
            parsed_events = AuthLogParser.parse_lines(lines, target_year, timezone_offset_hours)
        elif detected_format == "web_log":
            parsed_events = WebLogParser.parse_lines(lines)
        else:
            parsed_events = SyslogParser.parse_lines(lines, target_year, timezone_offset_hours)

        # Extract IOCs and MITRE ATT&CK mapping for each event
        all_iocs = []
        mitre_detections = []
        iocs_by_type = {"ipv4": set(), "domain": set(), "url": set(), "path": set(), "sha256": set()}

        for ev in parsed_events:
            event_id = str(uuid.uuid4())
            ev["id"] = event_id

            # Extract IOCs from line
            event_iocs = IOCExtractor.extract_from_text(ev["raw_line"])
            ev["iocs"] = event_iocs
            for ioc in event_iocs:
                t = ioc["type"]
                if t in iocs_by_type:
                    iocs_by_type[t].add(ioc["defanged"])

            # Map to MITRE
            ev_mitre = MitreMapper.map_event(ev["normalized_type"], ev["message"])
            ev["mitre_tags"] = ev_mitre
            for m in ev_mitre:
                if m not in mitre_detections:
                    mitre_detections.append(m)

        # Persist events in SQLite log_events table
        with get_db() as db:
            # Clear previous events for this file if re-analyzed
            db.execute("DELETE FROM log_events WHERE file_id = ?", (file_id,))
            for ev in parsed_events:
                db.execute(
                    """
                    INSERT INTO log_events (
                        id, file_id, case_id, timestamp, timestamp_epoch, host, process,
                        message, line_number, raw_line, normalized_type, relevance_score,
                        iocs, mitre_tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev["id"],
                        file_id,
                        case_id,
                        ev["timestamp"],
                        ev["timestamp_epoch"],
                        ev["host"],
                        ev["process"],
                        ev["message"],
                        ev["line_number"],
                        ev["raw_line"],
                        ev["normalized_type"],
                        ev["relevance_score"],
                        json.dumps(ev["iocs"]),
                        json.dumps(ev["mitre_tags"])
                    )
                )
            db.commit()

        # Defanged summary IOCs
        iocs_summary = {k: sorted(list(v)) for k, v in iocs_by_type.items() if len(v) > 0}

        return {
            "file_id": file_id,
            "case_id": case_id,
            "detected_format": detected_format,
            "total_lines_parsed": len(parsed_events),
            "assumptions": assumptions,
            "mitre_techniques": mitre_detections,
            "extracted_iocs": iocs_summary,
            "events_sample": parsed_events[:50]  # First 50 events for quick UI inspection
        }
