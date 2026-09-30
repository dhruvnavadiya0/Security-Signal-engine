"""
PDF report generator using ReportLab Platypus.

Generates structured, professional PDF security reports containing:
  1. Cover page with risk summary
  2. Executive summary
  3. Finding cards (ordered by risk score, descending)
  4. Appendix with raw data and scan metadata

PDFs are saved to ./reports/ with format: scan_{scan_id}_{YYYYMMDD_HHMMSS}.pdf
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from src.llm.fallback import get_fallback_analysis
from src.models.schemas import EnrichedFinding, RiskCategory, ScanReport

logger = logging.getLogger(__name__)

# Attempt to import ReportLab — graceful degradation if not installed
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm, inch
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        NextPageTemplate,
        PageBreak,
        PageTemplate,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning(
        "ReportLab is not installed. PDF reports will not be generated. "
        "Install with: pip install reportlab"
    )

# ── Constants ──────────────────────────────────────────────

REPORTS_DIR = Path("reports")

RISK_COLORS = {
    RiskCategory.CRITICAL: colors.HexColor("#DC2626"),
    RiskCategory.HIGH: colors.HexColor("#EA580C"),
    RiskCategory.MEDIUM: colors.HexColor("#CA8A04"),
    RiskCategory.LOW: colors.HexColor("#6B7280"),
}

RISK_BG_COLORS = {
    RiskCategory.CRITICAL: colors.HexColor("#FEE2E2"),
    RiskCategory.HIGH: colors.HexColor("#FFF7ED"),
    RiskCategory.MEDIUM: colors.HexColor("#FEFCE8"),
    RiskCategory.LOW: colors.HexColor("#F3F4F6"),
}


def _ensure_reports_dir() -> Path:
    """Create reports directory if it doesn't exist."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _build_filename(scan_id: str) -> str:
    """Generate PDF filename: scan_{scan_id}_{YYYYMMDD_HHMMSS}.pdf"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_{scan_id}_{ts}.pdf"


def plan_pdf_report_path(scan_id: str) -> str:
    """Plan and return the relative output path for a scan PDF."""
    reports_dir = _ensure_reports_dir()
    filename = _build_filename(scan_id)
    return str(reports_dir / filename)


def _escape(text: str) -> str:
    """Escape text for ReportLab Paragraph XML."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_pdf_report(report: ScanReport, output_path: str | None = None) -> str:
    """
    Generate a PDF report from a ScanReport and save to disk.

    Args:
        report: Complete scan report.

    Returns:
        Path to the generated PDF file (relative).

    Raises:
        RuntimeError: If ReportLab is not installed.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError(
            "ReportLab is not installed. Install with: pip install reportlab"
        )

    if output_path:
        filepath = Path(output_path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
    else:
        reports_dir = _ensure_reports_dir()
        filename = _build_filename(report.scan_id)
        filepath = reports_dir / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = _build_styles()
    story = []

    # ── Cover Page ──────────────────────────────────────────
    story.extend(_build_cover_page(report, styles))
    story.append(PageBreak())

    # ── Executive Summary ───────────────────────────────────
    story.extend(_build_executive_summary(report, styles))
    story.append(PageBreak())

    # ── Finding Cards ───────────────────────────────────────
    sorted_findings = sorted(
        report.findings, key=lambda f: f.risk_score, reverse=True
    )
    if sorted_findings:
        story.append(Paragraph("Detailed Findings", styles["heading1"]))
        story.append(Spacer(1, 6 * mm))

        for i, finding in enumerate(sorted_findings):
            story.extend(_build_finding_card(finding, i + 1, styles))
            story.append(Spacer(1, 8 * mm))

        story.append(PageBreak())

    # ── Appendix ────────────────────────────────────────────
    story.extend(_build_appendix(report, styles))

    # Build PDF
    try:
        doc.build(story)
        logger.info("PDF report generated: %s", filepath)
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        raise

    return str(filepath)


def _with_line_numbers(snippet: str, start_line: int) -> str:
    """Add line numbers if a snippet doesn't already include them."""
    if "|" in snippet[:30] or snippet.lstrip().startswith(">>>"):
        return snippet

    numbered: list[str] = []
    current = max(start_line, 1)
    for line in snippet.splitlines():
        numbered.append(f"{current:4d} | {line}")
        current += 1
    return "\n".join(numbered)


# ── Styles ─────────────────────────────────────────────────

def _build_styles() -> dict:
    """Build custom paragraph styles for the PDF."""
    base = getSampleStyleSheet()

    custom = {
        "title": ParagraphStyle(
            "CustomTitle",
            parent=base["Title"],
            fontSize=28,
            leading=34,
            alignment=TA_CENTER,
            spaceAfter=10 * mm,
            textColor=colors.HexColor("#1E293B"),
        ),
        "subtitle": ParagraphStyle(
            "CustomSubtitle",
            parent=base["Normal"],
            fontSize=14,
            leading=18,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=5 * mm,
        ),
        "heading1": ParagraphStyle(
            "CustomH1",
            parent=base["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=6 * mm,
            spaceBefore=4 * mm,
        ),
        "heading2": ParagraphStyle(
            "CustomH2",
            parent=base["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#334155"),
            spaceAfter=3 * mm,
            spaceBefore=2 * mm,
        ),
        "body": ParagraphStyle(
            "CustomBody",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155"),
            spaceAfter=3 * mm,
        ),
        "body_small": ParagraphStyle(
            "CustomBodySmall",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748B"),
        ),
        "code": ParagraphStyle(
            "CustomCode",
            parent=base["Code"],
            fontSize=8,
            leading=10,
            fontName="Courier",
            textColor=colors.HexColor("#1E293B"),
            backColor=colors.HexColor("#F1F5F9"),
            leftIndent=6 * mm,
            rightIndent=6 * mm,
            spaceBefore=2 * mm,
            spaceAfter=2 * mm,
        ),
        "badge_critical": ParagraphStyle(
            "BadgeCritical",
            parent=base["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=base["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=0,
            spaceAfter=2 * mm,
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#64748B"),
            fontName="Helvetica-Bold",
        ),
    }

    return custom


# ── Cover Page ─────────────────────────────────────────────

def _build_cover_page(report: ScanReport, styles: dict) -> list:
    """Build the cover page elements."""
    elements = []

    elements.append(Spacer(1, 40 * mm))
    elements.append(Paragraph("Security Scan Report", styles["title"]))
    elements.append(Spacer(1, 10 * mm))

    # Target
    target_display = _escape(report.target)
    elements.append(
        Paragraph(f"Target: {target_display}", styles["subtitle"])
    )

    # Date and scan ID
    try:
        ts = datetime.fromisoformat(report.timestamp.replace("Z", "+00:00"))
        date_str = ts.strftime("%B %d, %Y at %H:%M UTC")
    except Exception:
        date_str = report.timestamp[:19]

    elements.append(
        Paragraph(f"Scan Date: {date_str}", styles["subtitle"])
    )
    elements.append(
        Paragraph(f"Scan ID: {_escape(report.scan_id)}", styles["subtitle"])
    )

    elements.append(Spacer(1, 20 * mm))

    # Risk summary badge table
    summary = report.summary
    badge_data = [
        [
            _risk_count_cell("CRITICAL", summary.critical, RiskCategory.CRITICAL),
            _risk_count_cell("HIGH", summary.high, RiskCategory.HIGH),
            _risk_count_cell("MEDIUM", summary.medium, RiskCategory.MEDIUM),
            _risk_count_cell("LOW", summary.low, RiskCategory.LOW),
        ]
    ]

    badge_table = Table(badge_data, colWidths=[38 * mm, 38 * mm, 38 * mm, 38 * mm])
    badge_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
        ("BACKGROUND", (0, 0), (0, 0), RISK_COLORS[RiskCategory.CRITICAL]),
        ("BACKGROUND", (1, 0), (1, 0), RISK_COLORS[RiskCategory.HIGH]),
        ("BACKGROUND", (2, 0), (2, 0), RISK_COLORS[RiskCategory.MEDIUM]),
        ("BACKGROUND", (3, 0), (3, 0), RISK_COLORS[RiskCategory.LOW]),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 12),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))

    elements.append(badge_table)

    return elements


def _risk_count_cell(label: str, count: int, category: RiskCategory) -> str:
    """Format a risk count cell for the badge table."""
    return f"{count} {label}"


# ── Executive Summary ──────────────────────────────────────

def _build_executive_summary(report: ScanReport, styles: dict) -> list:
    """Build the executive summary section."""
    elements = []

    elements.append(Paragraph("Executive Summary", styles["heading1"]))
    elements.append(Spacer(1, 4 * mm))

    if report.executive_summary:
        summary_text = _escape(report.executive_summary)
        elements.append(Paragraph(summary_text, styles["body"]))
    else:
        elements.append(
            Paragraph("No executive summary available.", styles["body"])
        )

    # Summary statistics table
    elements.append(Spacer(1, 8 * mm))
    elements.append(Paragraph("Scan Statistics", styles["heading2"]))

    s = report.summary
    stats_data = [
        ["Metric", "Value"],
        ["Total Raw Findings", str(s.total_raw)],
        ["After Deduplication", str(s.after_dedup)],
        ["Critical Findings", str(s.critical)],
        ["High Findings", str(s.high)],
        ["Medium Findings", str(s.medium)],
        ["Low Findings", str(s.low)],
        ["Scan Duration", f"{report.scan_duration_ms / 1000:.1f}s"],
    ]

    stats_table = Table(stats_data, colWidths=[70 * mm, 50 * mm])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC"),
        ]),
        ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
    ]))

    elements.append(stats_table)

    return elements


# ── Finding Cards ──────────────────────────────────────────

def _build_finding_card(
    finding: EnrichedFinding, index: int, styles: dict
) -> list:
    """Build a single finding card section."""
    elements = []

    cat = finding.risk_category
    color = RISK_COLORS.get(cat, colors.gray)
    bg_color = RISK_BG_COLORS.get(cat, colors.HexColor("#F3F4F6"))

    # Finding header with badge
    header_text = (
        f'<font color="{color.hexval()}">[{cat.value}]</font> '
        f"#{index}: {_escape(finding.title)}"
    )
    elements.append(Paragraph(header_text, styles["finding_title"]))

    # Metadata table
    meta_rows = [
        ["Risk Score", f"{finding.risk_score:.4f}"],
        ["Affected Location", f"{_escape(finding.file)}:{finding.line_start}"],
        ["Vulnerability Type", _escape(finding.vuln_type)],
    ]
    if finding.cwe_id:
        meta_rows.append(["CWE ID", _escape(finding.cwe_id)])
    if finding.sources:
        meta_rows.append(["Detected By", ", ".join(finding.sources)])

    meta_table = Table(meta_rows, colWidths=[40 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748B")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1E293B")),
        ("TOPPADDING", (0, 0), (-1, -1), 1 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1 * mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm),
        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 3 * mm))

    # Explanation
    explanation = finding.llm_explanation or finding.description
    if explanation:
        elements.append(Paragraph("Explanation", styles["label"]))
        elements.append(Paragraph(_escape(explanation[:500]), styles["body"]))

    # Code snippet / HTTP excerpt
    if finding.code_snippet:
        elements.append(Paragraph("Code or HTTP Excerpt", styles["label"]))
        snippet = finding.code_snippet[:600]
        elements.append(Preformatted(_with_line_numbers(snippet, finding.line_start), styles["code"]))
        elements.append(Spacer(1, 2 * mm))

    # Business impact
    if finding.business_impact:
        elements.append(Paragraph("Business Impact", styles["label"]))
        elements.append(
            Paragraph(_escape(finding.business_impact[:300]), styles["body"])
        )

    # Fix recommendation (deterministic + LLM)
    deterministic_fix = get_fallback_analysis(
        finding.vuln_type,
        description=finding.description,
        code_snippet=finding.code_snippet or "",
        file_path=finding.file,
        cwe_id=finding.cwe_id or "",
    ).get("fix_suggestion", "")

    llm_fix = finding.fix_suggestion or ""

    # Choose the best fix: LLM fix if it exists and differs, otherwise rule-based.
    # The LLM is now prompted to evaluate both and return a single comprehensive fix.
    best_fix = llm_fix.strip() if llm_fix.strip() else deterministic_fix.strip()

    if best_fix:
        elements.append(Paragraph("Fix Recommendation", styles["label"]))
        elements.append(
            Paragraph(
                f"<b>Best Fix:</b> {_escape(best_fix[:800])}",
                styles["body"],
            )
        )

    # Separator line
    separator = Table([[""]], colWidths=[160 * mm])
    separator.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
    ]))
    elements.append(separator)

    return elements


# ── Appendix ────────────────────────────────────────────────

def _build_appendix(report: ScanReport, styles: dict) -> list:
    """Build the appendix section with metadata and raw data."""
    elements = []

    elements.append(Paragraph("Appendix", styles["heading1"]))
    elements.append(Spacer(1, 4 * mm))

    # Deduplication stats
    elements.append(Paragraph("Deduplication Statistics", styles["heading2"]))
    s = report.summary
    if s.total_raw > 0:
        reduction = ((s.total_raw - s.after_dedup) / s.total_raw) * 100
    else:
        reduction = 0

    dedup_text = (
        f"Total raw findings: {s.total_raw} | "
        f"After deduplication: {s.after_dedup} | "
        f"Reduction: {reduction:.0f}%"
    )
    elements.append(Paragraph(dedup_text, styles["body"]))
    elements.append(Spacer(1, 4 * mm))

    # Scan metadata
    elements.append(Paragraph("Scan Metadata", styles["heading2"]))
    meta_rows = [
        ["Scan ID", report.scan_id],
        ["Target", _escape(report.target[:100])],
        ["Timestamp", report.timestamp],
        ["Duration", f"{report.scan_duration_ms / 1000:.1f}s"],
        ["Scanners Used", ", ".join(report.scanners_used) if report.scanners_used else "unknown"],
        [
            "Scanner Versions",
            _escape(
                ", ".join(
                    f"{name}={version}" for name, version in report.scanner_versions.items()
                )
            ) if report.scanner_versions else "unknown",
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[40 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 6 * mm))

    # Full JSON findings dump (formatted)
    elements.append(Paragraph("Raw Findings Data (JSON)", styles["heading2"]))
    try:
        json_data = report.model_dump(mode="json")
        # Only include findings array to keep appendix manageable
        findings_json = json.dumps(
            json_data.get("findings", []),
            indent=2,
            default=str,
        )
        elements.append(
            Preformatted(findings_json, styles["code"])
        )
    except Exception as e:
        elements.append(
            Paragraph(f"Error serializing findings: {_escape(str(e))}", styles["body"])
        )

    return elements
