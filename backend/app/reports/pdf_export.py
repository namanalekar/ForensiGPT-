from pathlib import Path
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from app.core.config import settings

class PDFReportExporter:
    """Generates professional, security-console styled DFIR forensic PDF dossiers."""

    @classmethod
    def export_pdf(cls, case_title: str, report_data: dict, files: list[dict], dest_path: Path) -> Path:
        settings.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(dest_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ConsoleTitle',
            parent=styles['Heading1'],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0F172A"),
            fontName="Helvetica-Bold"
        )
        sub_style = ParagraphStyle(
            'ConsoleSub',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569")
        )
        h2_style = ParagraphStyle(
            'ConsoleH2',
            parent=styles['Heading2'],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=10,
            spaceAfter=6,
            fontName="Helvetica-Bold"
        )
        body_style = ParagraphStyle(
            'ConsoleBody',
            parent=styles['BodyText'],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        disclaimer_style = ParagraphStyle(
            'Disclaimer',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#DC2626"),
            fontName="Helvetica-Bold"
        )

        story = []

        # 1. Header & Title
        story.append(Paragraph(f"FORENSIGPT INCIDENT REPORT: {case_title.upper()}", title_style))
        story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Platform: ForensiGPT DFIR Engine v1.0", sub_style))
        story.append(Spacer(1, 12))

        # 2. Mandatory Disclaimer
        disclaimer_text = "⚠ MANDATORY FORENSIC DISCLAIMER: This dossier contains deterministic findings contextualized by AI. Verify all findings independently. No static analysis can mathematically prove a file is clean or safe."
        story.append(Paragraph(disclaimer_text, disclaimer_style))
        story.append(Spacer(1, 10))

        # 3. Verdict & Risk Score
        risk = report_data.get("risk_score", 0)
        verdict = report_data.get("verdict", "Unverified")
        verdict_color = "#DC2626" if risk >= 70 else ("#EA580C" if risk >= 40 else "#16A34A")

        summary_table_data = [
            [Paragraph("<b>OVERALL VERDICT</b>", body_style), Paragraph(f"<b><font color='{verdict_color}'>{verdict.upper()}</font></b>", body_style)],
            [Paragraph("<b>COMPUTED RISK SCORE</b>", body_style), Paragraph(f"<b>{risk}/100</b>", body_style)],
            [Paragraph("<b>EXECUTIVE SUMMARY</b>", body_style), Paragraph(report_data.get("executive_summary", ""), body_style)]
        ]
        t_summary = Table(summary_table_data, colWidths=[150, 390])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 14))

        # 4. Chain of Custody Table
        story.append(Paragraph("1. CHAIN OF CUSTODY & FILE IDENTIFICATION", h2_style))
        custody_data = [["Filename", "Size", "True Format", "SHA-256 Digest"]]
        for f in files:
            custody_data.append([
                f.get("original_filename", ""),
                f"{f.get('file_size', 0):,} B",
                f.get("true_file_type", ""),
                f.get("sha256", "")[:32] + "..."
            ])
        t_custody = Table(custody_data, colWidths=[130, 60, 80, 270])
        t_custody.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0F172A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('BOTTOMPADDING', (0,0), (-1,0), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_custody)
        story.append(Spacer(1, 14))

        # 5. Key Findings Table
        story.append(Paragraph("2. KEY FORENSIC FINDINGS", h2_style))
        findings_data = [["Evidence ID", "Severity", "Finding Title", "Plain Language Explanation"]]
        for kf in report_data.get("key_findings", []):
            findings_data.append([
                Paragraph(f"<b>{kf.get('evidence_id', '')}</b>", body_style),
                Paragraph(kf.get('severity', ''), body_style),
                Paragraph(kf.get('title', ''), body_style),
                Paragraph(kf.get('plain_explanation', ''), body_style),
            ])
        t_find = Table(findings_data, colWidths=[90, 60, 140, 250])
        t_find.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_find)
        story.append(Spacer(1, 14))

        # 6. Observed Facts vs Hypotheses
        story.append(Paragraph("3. OBSERVED FACTS & HYPOTHESES", h2_style))
        story.append(Paragraph("<b>Observed Facts:</b>", body_style))
        for fact in report_data.get("observed_facts", []):
            story.append(Paragraph(f"• {fact}", body_style))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Analytical Hypotheses:</b>", body_style))
        for hyp in report_data.get("hypotheses", []):
            story.append(Paragraph(
                f"• [{hyp.get('confidence', 'Medium').upper()} CONFIDENCE] {hyp.get('hypothesis', '')} "
                f"(Missing Evidence: {hyp.get('missing_evidence', 'None')})",
                body_style
            ))
        story.append(Spacer(1, 14))

        # 7. Next Steps & Assumptions
        story.append(Paragraph("4. RECOMMENDED NEXT STEPS & ASSUMPTIONS", h2_style))
        for step in report_data.get("recommended_next_steps", []):
            story.append(Paragraph(f"→ {step}", body_style))
        story.append(Spacer(1, 6))
        for asm in report_data.get("limitations_and_assumptions", []):
            story.append(Paragraph(f"<i>Assumed / Caveat: {asm}</i>", body_style))

        doc.build(story)
        return dest_path
