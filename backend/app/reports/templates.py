from typing import Any
from app.ai.schemas import (
    ForensicReportSchema,
    StructuredFindingItem,
    StructuredTimelineItem,
    StructuredHypothesis
)

class OfflineReportBuilder:
    """
    Deterministic template-based forensic report builder.
    Used in Privacy Mode (offline, no external AI calls) or when no Gemini API key is configured.
    Converts raw deterministic evidence into structured reports with evidence IDs.
    """

    @classmethod
    def generate_report(
        cls,
        case_title: str,
        files: list[dict[str, Any]],
        analysis_map: dict[str, Any],
        sync_result: dict[str, Any] | None,
        risk_score: int,
        verdict: str,
        mode: str = "analyst"
    ) -> ForensicReportSchema:
        key_findings: list[StructuredFindingItem] = []
        observed_facts: list[str] = []
        timeline_items: list[StructuredTimelineItem] = []
        hypotheses: list[StructuredHypothesis] = []

        # 1. Harvest Findings from files and analysis
        for f in files:
            file_id = f["id"]
            fname = f["original_filename"]

            # Extension mismatch
            if not f.get("extension_match", True):
                key_findings.append(StructuredFindingItem(
                    evidence_id="EVID-MISC-002",
                    severity="High",
                    title=f"Extension Mismatch in {fname}",
                    plain_explanation=(
                        f"The file '{fname}' claims extension '{f.get('true_file_type')}', but its internal magic bytes "
                        f"identify it as '{f.get('true_file_type')}'. Files disguised with misleading extensions are "
                        "frequently used in social engineering to bypass email security gateways."
                    )
                ))

            # Trailing data
            if f.get("has_trailing_data"):
                key_findings.append(StructuredFindingItem(
                    evidence_id="EVID-STEGO-001",
                    severity="High",
                    title=f"Trailing Data Beyond EOF in {fname}",
                    plain_explanation=(
                        f"The file contains {f.get('trailing_bytes_count', 0):,} bytes appended past the valid "
                        "end-of-file marker. This unreferenced trailing payload indicates potential steganographic overlay "
                        "or file concatenation."
                    )
                ))

            # Check deep analysis items
            if file_id in analysis_map:
                res = analysis_map[file_id]
                for ev in res.get("evidence_items", []):
                    key_findings.append(StructuredFindingItem(
                        evidence_id=ev.get("evidence_id", "EVID-GEN-001"),
                        severity=ev.get("severity", "Medium"),
                        title=ev.get("title", "Forensic Finding"),
                        plain_explanation=ev.get("description", "")
                    ))

        # 2. Timeline items from Sync Result if available
        corr_narrative = "No Image-to-Log synchronization was requested for this case."
        if sync_result and sync_result.get("correlated_events"):
            events = sync_result["correlated_events"]
            corr_narrative = (
                f"Successfully correlated {len(events)} log events within a temporal window of "
                f"±{sync_result.get('window_seconds', 300)}s around the anchor timestamp. "
            )
            for ev in events:
                timeline_items.append(StructuredTimelineItem(
                    timestamp_utc=ev.get("timestamp") or "N/A",
                    event_id=ev.get("id"),
                    summary=f"[{ev.get('normalized_type', '').upper()}] {ev.get('process', '')}: {ev.get('message', '')} ({ev.get('delta_desc', '')})",
                    is_observed_fact=True
                ))
                observed_facts.append(
                    f"At {ev.get('timestamp')}, {ev.get('process')} reported: {ev.get('message')} ({ev.get('delta_desc')})"
                )

            # Build hypothesis based on correlated patterns
            for pat in sync_result.get("before_after_patterns", []):
                hypotheses.append(StructuredHypothesis(
                    hypothesis=f"User activity at timestamp correlated directly with artifact generation: {pat.get('description')}",
                    confidence="High" if pat.get("relevance", 0) >= 80 else "Medium",
                    supporting_evidence_ids=[pat.get("event_id", "EVID-LOG-001")],
                    missing_evidence="Host memory acquisition or shell session command history."
                ))

        if not observed_facts:
            observed_facts.append(f"Case '{case_title}' contains {len(files)} files subjected to deterministic static analysis.")

        # Executive summary
        exec_summary = (
            f"ForensiGPT automated deterministic analysis of case '{case_title}'. "
            f"Evaluated {len(files)} files resulting in an overall risk assessment of {risk_score}/100 ({verdict}). "
            f"Detected {len(key_findings)} evidence items across file headers, metadata, and log traces."
        )

        return ForensicReportSchema(
            executive_summary=exec_summary,
            verdict=verdict,
            risk_score=risk_score,
            key_findings=key_findings,
            timeline_narrative=timeline_items,
            image_log_correlation_narrative=corr_narrative,
            observed_facts=observed_facts,
            hypotheses=hypotheses if hypotheses else [
                StructuredHypothesis(
                    hypothesis="No conclusive multi-event attack hypothesis generated.",
                    confidence="Low",
                    supporting_evidence_ids=[],
                    missing_evidence="Additional endpoint and perimeter telemetry."
                )
            ],
            recommended_next_steps=[
                "Isolate suspicious files in an air-gapped forensic analysis sandbox or virtual machine.",
                "Review external perimeter firewall logs for communication with extracted IOC IP addresses.",
                "Verify system access credentials if authentication brute-force patterns were observed."
            ],
            limitations_and_assumptions=[
                "Deterministic static analysis evaluates structural and cryptographic markers only; it cannot prove absence of malicious intent.",
                "Error Level Analysis (ELA) and LSB statistics are probabilistic heuristics, not mathematical proofs of tampering.",
                "Syslog events without year tags are normalized using specified target year assumptions."
            ]
        )
