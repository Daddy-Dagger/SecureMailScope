"""PDF report generator for SecureMailScope.

Renders validated analysis results into a standalone, printable, offline-ready
PDF forensic report using ReportLab.

Conforms strictly to:
- shared/contracts/analysis_result_schema.json
- shared/contracts/session_schema.json
- shared/contracts/finding_schema.json
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.app.models.analysis import AnalysisResultResponse

# Severity color mapping
_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#2563eb"),
    "INFO": colors.HexColor("#64748b"),
}


class _NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that computes total page count and draws headers/footers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def _draw_header_footer(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running header on page 2 and beyond
        if self._pageNumber > 1:
            self.drawString(
                36,
                11 * 72 - 28,
                "SecureMailScope — Email Cryptographic Security Analysis (SIH26159)",
            )
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(36, 11 * 72 - 32, 8.5 * 72 - 36, 11 * 72 - 32)

        # Running footer on all pages
        self.setFont("Helvetica", 8)
        self.drawString(
            36,
            22,
            "SecureMailScope Forensic Report • SIH26159 • Confidential & Privacy-Preserving",
        )
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 36, 22, page_text)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(36, 32, 8.5 * 72 - 36, 32)

        self.restoreState()


def _get_report_styles() -> dict[str, ParagraphStyle]:
    """Build dedicated typography styles for the PDF report."""
    base_styles = getSampleStyleSheet()

    styles: dict[str, ParagraphStyle] = {
        "DocTitle": ParagraphStyle(
            "DocTitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        ),
        "DocSubtitle": ParagraphStyle(
            "DocSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=14,
        ),
        "SectionHeading": ParagraphStyle(
            "SectionHeading",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True,
        ),
        "NormalText": ParagraphStyle(
            "NormalText",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b"),
        ),
        "MetaLabel": ParagraphStyle(
            "MetaLabel",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#475569"),
        ),
        "MetaValue": ParagraphStyle(
            "MetaValue",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0f172a"),
        ),
        "CodeText": ParagraphStyle(
            "CodeText",
            parent=base_styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=0,
        ),
        "TableCell": ParagraphStyle(
            "TableCell",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#1e293b"),
        ),
        "TableCellCode": ParagraphStyle(
            "TableCellCode",
            parent=base_styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        ),
        "FindingTitle": ParagraphStyle(
            "FindingTitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#0f172a"),
        ),
        "FindingBody": ParagraphStyle(
            "FindingBody",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155"),
            spaceBefore=3,
            spaceAfter=4,
        ),
        "RecLabel": ParagraphStyle(
            "RecLabel",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#15803d"),
        ),
        "RecText": ParagraphStyle(
            "RecText",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#166534"),
        ),
        "EmptyState": ParagraphStyle(
            "EmptyState",
            parent=base_styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#64748b"),
            alignment=1,
            spaceBefore=8,
            spaceAfter=8,
        ),
    }

    return styles


def generate_pdf_report(
    analysis_result: AnalysisResultResponse | dict[str, Any],
    output_path: str | Path | None = None,
) -> Path | bytes:
    """Generate a clean, standalone, printable PDF forensic report.

    Validates that input strictly conforms to
    `shared/contracts/analysis_result_schema.json`.

    Args:
        analysis_result: An AnalysisResultResponse model instance or a raw dictionary
            representing analysis results.
        output_path: Optional destination file path. If provided, writes the PDF
            to disk and returns the Path. If omitted/None, returns raw PDF bytes.

    Returns:
        Path to the written PDF file (if output_path provided) or bytes (if None).

    Raises:
        ValidationError: If the input data violates the shared schema contract.
        TypeError: If input is neither an AnalysisResultResponse nor a dictionary.
    """
    if isinstance(analysis_result, AnalysisResultResponse):
        validated_model = analysis_result
    elif isinstance(analysis_result, dict):
        validated_model = AnalysisResultResponse.model_validate(analysis_result)
    else:
        raise TypeError(
            f"Expected AnalysisResultResponse or dict, got {type(analysis_result).__name__}"
        )

    # Determine destination stream
    if output_path is not None:
        dest_path = Path(output_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        target = str(dest_path)
    else:
        dest_path = None
        target = io.BytesIO()

    # Printable page width: 612 - 72 = 540 pt
    doc = SimpleDocTemplate(
        target,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=42,
        bottomMargin=42,
    )

    styles = _get_report_styles()
    story: list[Any] = []

    # 1. Header & Project Identification
    story.append(Paragraph("SecureMailScope — Email Cryptographic Security Analysis", styles["DocTitle"]))
    story.append(
        Paragraph("Passive Network Forensics Forensic Report &bull; SIH26159", styles["DocSubtitle"])
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e293b"), spaceAfter=10))

    # 2. Capture Overview & Assessment Table
    story.append(Paragraph("Capture Overview &amp; Assessment", styles["SectionHeading"]))

    score_display = (
        str(validated_model.overall_score)
        if validated_model.overall_score is not None
        else "Not available"
    )
    risk_display = (
        validated_model.risk_level
        if validated_model.risk_level is not None
        else "Not available"
    )

    overview_data = [
        [
            Paragraph("Analyzed File:", styles["MetaLabel"]),
            Paragraph(escape(validated_model.file), styles["CodeText"]),
            Paragraph("Overall Score:", styles["MetaLabel"]),
            Paragraph(escape(score_display), styles["MetaValue"]),
        ],
        [
            Paragraph("Total Packets:", styles["MetaLabel"]),
            Paragraph(str(validated_model.packet_count), styles["MetaValue"]),
            Paragraph("Risk Level:", styles["MetaLabel"]),
            Paragraph(escape(risk_display), styles["MetaValue"]),
        ],
        [
            Paragraph("Protocol Sessions:", styles["MetaLabel"]),
            Paragraph(
                f"SMTP: {validated_model.summary.smtp_sessions} &bull; "
                f"IMAP: {validated_model.summary.imap_sessions} &bull; "
                f"POP3: {validated_model.summary.pop3_sessions}",
                styles["MetaValue"],
            ),
            Paragraph("Assessment Status:", styles["MetaLabel"]),
            Paragraph("Deterministic analysis complete", styles["MetaValue"]),
        ],
    ]

    overview_table = Table(overview_data, colWidths=[110, 160, 110, 160])
    overview_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(overview_table)
    story.append(Spacer(1, 12))

    # 3. Extracted Email Sessions
    story.append(Paragraph("Extracted Email Sessions", styles["SectionHeading"]))

    if validated_model.sessions:
        # Col widths sum to 540 pt: 70 + 45 + 105 + 105 + 45 + 85 + 85
        session_col_widths = [70, 45, 105, 105, 45, 85, 85]
        session_table_data = [
            [
                Paragraph("Session ID", styles["TableHeader"]),
                Paragraph("Protocol", styles["TableHeader"]),
                Paragraph("Client Endpoint", styles["TableHeader"]),
                Paragraph("Server Endpoint", styles["TableHeader"]),
                Paragraph("Packets", styles["TableHeader"]),
                Paragraph("Start Time (UTC)", styles["TableHeader"]),
                Paragraph("End Time (UTC)", styles["TableHeader"]),
            ]
        ]

        for session in validated_model.sessions:
            session_table_data.append(
                [
                    Paragraph(escape(session.session_id), styles["TableCellCode"]),
                    Paragraph(escape(session.protocol), styles["TableCell"]),
                    Paragraph(f"{escape(session.client_ip)}:{session.client_port}", styles["TableCellCode"]),
                    Paragraph(f"{escape(session.server_ip)}:{session.server_port}", styles["TableCellCode"]),
                    Paragraph(str(session.packet_count), styles["TableCell"]),
                    Paragraph(escape(session.start_time), styles["TableCell"]),
                    Paragraph(escape(session.end_time), styles["TableCell"]),
                ]
            )

        session_table = Table(session_table_data, colWidths=session_col_widths, repeatRows=1)
        session_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                    ("TOPPADDING", (0, 0), (-1, 0), 5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 1), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                ]
            )
        )
        story.append(session_table)
    else:
        story.append(Paragraph("No sessions detected.", styles["EmptyState"]))

    story.append(Spacer(1, 12))

    # 4. Cryptographic Security Findings
    story.append(Paragraph("Cryptographic Security Findings", styles["SectionHeading"]))

    if validated_model.findings:
        for finding in validated_model.findings:
            sev_color = _SEVERITY_COLORS.get(finding.severity, colors.HexColor("#64748b"))

            # Header row: Title + ID on left, Severity tag on right
            header_data = [
                [
                    Paragraph(
                        f"<b>{escape(finding.title)}</b> <font color='#64748b'>({escape(finding.finding_id)})</font>",
                        styles["FindingTitle"],
                    ),
                    Paragraph(f"<b>{escape(finding.severity)}</b>", styles["TableCell"]),
                ]
            ]
            header_table = Table(header_data, colWidths=[460, 80])
            header_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (1, 0), (1, 0), sev_color),
                        ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                        ("ALIGN", (1, 0), (1, 0), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )

            # Recommendation Box
            rec_content = [
                Paragraph("<b>Remediation Recommendation:</b>", styles["RecLabel"]),
                Paragraph(escape(finding.recommendation), styles["RecText"]),
            ]
            rec_table = Table([[rec_content]], colWidths=[528])
            rec_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                        ("LINELEFT", (0, 0), (0, -1), 3, colors.HexColor("#22c55e")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbf7d0")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            finding_box_data = [
                [header_table],
                [Paragraph(escape(finding.explanation), styles["FindingBody"])],
                [rec_table],
            ]

            finding_box = Table(finding_box_data, colWidths=[540])
            finding_box.setStyle(
                TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )

            story.append(KeepTogether([finding_box, Spacer(1, 8)]))
    else:
        story.append(Paragraph("No security findings available.", styles["EmptyState"]))

    # Build the PDF using the two-pass NumberedCanvas
    doc.build(story, canvasmaker=_NumberedCanvas)

    if dest_path is not None:
        return dest_path

    # Return in-memory bytes if no output path was supplied
    assert isinstance(target, io.BytesIO)
    return target.getvalue()


def export_pdf_report(
    analysis_result: AnalysisResultResponse | dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Export the PDF forensic report to a file on disk."""
    result = generate_pdf_report(analysis_result, output_path=output_path)
    assert isinstance(result, Path)
    return result
