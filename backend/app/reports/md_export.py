from datetime import datetime, timezone
import csv
import io
from pathlib import Path

class MarkdownReportExporter:
    """Exports forensic report formatted in clean GitHub-Flavored Markdown."""

    @classmethod
    def export_markdown(cls, case_title: str, report_data: dict, files: list[dict]) -> str:
        lines = []
        lines.append(f"# ForensiGPT Incident Dossier: {case_title}")
        lines.append(f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Platform: ForensiGPT DFIR Engine v1.0*")
        lines.append("")
        lines.append("> [!WARNING]")
        lines.append("> **Mandatory Forensic Disclaimer**: This dossier contains deterministic findings contextualized by AI. Verify all findings independently. No static analysis can mathematically prove a file is clean or safe.")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"**Overall Verdict**: `{report_data.get('verdict', 'Unverified')}`")
        lines.append(f"**Risk Score**: **{report_data.get('risk_score', 0)}/100**")
        lines.append("")
        lines.append(report_data.get("executive_summary", ""))
        lines.append("")
        lines.append("## 1. Chain of Custody & File Identification")
        lines.append("| Original Filename | Size (Bytes) | True Format | SHA-256 Digest | SHA-1 Digest | MD5 Digest |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in files:
            lines.append(
                f"| `{f.get('original_filename')}` | {f.get('file_size', 0):,} | `{f.get('true_file_type')}` | "
                f"`{f.get('sha256')}` | `{f.get('sha1')}` | `{f.get('md5')}` |"
            )
        lines.append("")
        lines.append("## 2. Key Forensic Findings")
        lines.append("| Evidence ID | Severity | Finding Title | Explanation |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for kf in report_data.get("key_findings", []):
            lines.append(
                f"| `{kf.get('evidence_id')}` | **{kf.get('severity')}** | {kf.get('title')} | {kf.get('plain_explanation')} |"
            )
        lines.append("")
        lines.append("## 3. Image-to-Log Synchronization Narrative")
        lines.append(report_data.get("image_log_correlation_narrative", "N/A"))
        lines.append("")
        lines.append("## 4. Observed Facts & Hypotheses")
        lines.append("### Observed Facts")
        for fact in report_data.get("observed_facts", []):
            lines.append(f"- {fact}")
        lines.append("")
        lines.append("### Hypotheses")
        for hyp in report_data.get("hypotheses", []):
            lines.append(
                f"- **[{hyp.get('confidence', 'Medium').upper()} CONFIDENCE]**: {hyp.get('hypothesis')} "
                f"*(Missing Evidence: {hyp.get('missing_evidence')})*"
            )
        lines.append("")
        lines.append("## 5. Recommended Next Steps")
        for step in report_data.get("recommended_next_steps", []):
            lines.append(f"1. {step}")
        lines.append("")
        lines.append("## 6. Limitations & Assumptions")
        for asm in report_data.get("limitations_and_assumptions", []):
            lines.append(f"- *{asm}*")
        lines.append("")

        return "\n".join(lines)

class CSVTimelineExporter:
    """Exports event timeline to RFC 4180 compliant CSV for SIEM ingestion."""

    @classmethod
    def export_csv(cls, timeline_events: list[dict]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Line", "Timestamp_UTC", "Epoch", "Host", "Process", "Normalized_Type", "Relevance", "Delta_Seconds", "Message"])
        for ev in timeline_events:
            writer.writerow([
                ev.get("line_number", ""),
                ev.get("timestamp", ""),
                ev.get("timestamp_epoch", ""),
                ev.get("host", ""),
                ev.get("process", ""),
                ev.get("normalized_type", ""),
                ev.get("relevance_score", ""),
                ev.get("delta_seconds", ""),
                ev.get("message", "")
            ])
        return output.getvalue()
