"""
CLI report generator.

Produces human-readable, color-coded console output using the Rich
library. Organized per PRD Section 5.7.2:
  - Scan metadata header
  - Executive summary paragraph
  - Critical findings (detailed)
  - High findings (detailed)
  - Medium findings (summary)
  - Low findings (count only)
  - Footer with scan duration and deduplication stats
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from src.llm.fallback import get_fallback_analysis
from src.models.schemas import EnrichedFinding, RiskCategory, ScanReport

console = Console()


# Color map from PRD Section 8.1
_CATEGORY_STYLES = {
    RiskCategory.CRITICAL: "bold red",
    RiskCategory.HIGH: "bold bright_red",
    RiskCategory.MEDIUM: "bold yellow",
    RiskCategory.LOW: "dim white",
}

_CATEGORY_ICONS = {
    RiskCategory.CRITICAL: "🔴",
    RiskCategory.HIGH: "🟠",
    RiskCategory.MEDIUM: "🟡",
    RiskCategory.LOW: "⚪",
}


def _format_severity_badge(category: RiskCategory) -> Text:
    """Create a color-coded severity badge."""
    style = _CATEGORY_STYLES.get(category, "white")
    icon = _CATEGORY_ICONS.get(category, "●")
    return Text(f" {icon} {category.value} ", style=style)


def _format_finding_detail(finding: EnrichedFinding) -> Panel:
    """Format a single finding as a detailed Rich panel."""
    style = _CATEGORY_STYLES.get(finding.risk_category, "white")
    border_style = {
        RiskCategory.CRITICAL: "red",
        RiskCategory.HIGH: "bright_red",
        RiskCategory.MEDIUM: "yellow",
        RiskCategory.LOW: "dim",
    }.get(finding.risk_category, "dim")

    content = Text()

    # Title and metadata
    content.append(f"📍 {finding.file}", style="bold cyan")
    content.append(f" (line {finding.line_start})\n", style="dim")
    content.append(f"   Type: ", style="dim")
    content.append(f"{finding.vuln_type}\n", style="bold")
    content.append(f"   Score: ", style="dim")
    content.append(f"{finding.risk_score:.2f}", style=style)
    if finding.cwe_id:
        content.append(f"  |  CWE: {finding.cwe_id}", style="dim")
    if finding.sources:
        content.append(f"  |  Sources: {', '.join(finding.sources)}", style="dim")
    content.append("\n\n")

    # Description
    if finding.description:
        content.append("   Description: ", style="dim bold")
        content.append(f"{finding.description[:200]}\n\n")

    # Code snippet
    if finding.code_snippet:
        content.append("   Code:\n", style="dim bold")
        for line in finding.code_snippet.split("\n")[:7]:
            if line.startswith(">>>"):
                content.append(f"   {line}\n", style="bold red")
            else:
                content.append(f"   {line}\n", style="dim")
        content.append("\n")

    # LLM Explanation
    if finding.llm_explanation:
        content.append("   💡 Why This Matters:\n", style="bold")
        content.append(f"   {finding.llm_explanation}\n\n")

    # Best Fix Recommendation
    rule_based_fix = get_fallback_analysis(
        finding.vuln_type,
        description=finding.description,
        code_snippet=finding.code_snippet or "",
        file_path=finding.file,
        cwe_id=finding.cwe_id or "",
    ).get("fix_suggestion", "")

    llm_fix = finding.fix_suggestion or ""
    
    best_fix = llm_fix.strip() if llm_fix.strip() else rule_based_fix.strip()

    if best_fix:
        content.append("   🔧 Best Fix:\n", style="bold green")
        content.append(f"   {best_fix}\n\n")

    # Business impact
    if finding.business_impact:
        content.append("   ⚠️  Impact: ", style="bold yellow")
        content.append(f"{finding.business_impact}\n")

    return Panel(
        content,
        title=f"{_CATEGORY_ICONS.get(finding.risk_category, '●')} {finding.title}",
        border_style=border_style,
        expand=True,
        padding=(0, 1),
    )


def _format_finding_summary_row(finding: EnrichedFinding) -> str:
    """Format a single finding as a one-line summary."""
    icon = _CATEGORY_ICONS.get(finding.risk_category, "●")
    return (
        f"  {icon} [{finding.risk_score:.2f}] "
        f"{finding.vuln_type:20s} "
        f"{finding.file}:{finding.line_start}"
    )


def print_cli_report(report: ScanReport) -> None:
    """
    Print a complete scan report to the console.
    
    Structure follows PRD Section 5.7.2:
    1. Scan metadata header
    2. Executive summary
    3. Critical findings (detailed)
    4. High findings (detailed)
    5. Medium findings (summary)
    6. Low findings (count only)
    7. Footer with stats
    """
    console.print()

    # ── Header ──────────────────────────────────────────────
    header = Table(show_header=False, box=box.SIMPLE_HEAVY, expand=True, padding=(0, 2))
    header.add_column(style="bold cyan", ratio=1)
    header.add_column(style="dim", ratio=1, justify="right")
    header.add_row(
        "🛡️  SECURITY SIGNAL ENGINE",
        f"Scan ID: {report.scan_id[:8]}...",
    )
    header.add_row(
        f"Target: {report.target}",
        f"Time: {report.timestamp[:19]}",
    )
    console.print(header)
    console.print()

    # ── Summary stats ───────────────────────────────────────
    summary = report.summary
    before = f"{summary.total_raw} findings"
    after_parts = []
    if summary.critical > 0:
        after_parts.append(f"[bold red]{summary.critical} CRITICAL[/]")
    if summary.high > 0:
        after_parts.append(f"[bold bright_red]{summary.high} HIGH[/]")
    if summary.medium > 0:
        after_parts.append(f"[bold yellow]{summary.medium} MEDIUM[/]")
    if summary.low > 0:
        after_parts.append(f"[dim]{summary.low} LOW[/]")

    dedup_line = (
        f"  📊 {before} → {summary.after_dedup} unique → "
        + " | ".join(after_parts) if after_parts else f"  📊 {before} → 0 issues"
    )
    console.print(dedup_line)
    console.print()

    # ── Executive summary ───────────────────────────────────
    if report.executive_summary:
        console.print(
            Panel(
                report.executive_summary,
                title="📋 Executive Summary",
                border_style="blue",
                expand=True,
                padding=(1, 2),
            )
        )
        console.print()

    # ── Critical findings (detailed) ────────────────────────
    critical_findings = [
        f for f in report.findings if f.risk_category == RiskCategory.CRITICAL
    ]
    if critical_findings:
        console.print(
            f"  [bold red]━━━ CRITICAL FINDINGS ({len(critical_findings)}) ━━━[/]"
        )
        console.print()
        for finding in critical_findings:
            console.print(_format_finding_detail(finding))
            console.print()

    # ── High findings (detailed) ────────────────────────────
    high_findings = [
        f for f in report.findings if f.risk_category == RiskCategory.HIGH
    ]
    if high_findings:
        console.print(
            f"  [bold bright_red]━━━ HIGH FINDINGS ({len(high_findings)}) ━━━[/]"
        )
        console.print()
        for finding in high_findings:
            console.print(_format_finding_detail(finding))
            console.print()

    # ── Medium findings (summary) ───────────────────────────
    medium_findings = [
        f for f in report.findings if f.risk_category == RiskCategory.MEDIUM
    ]
    if medium_findings:
        console.print(
            f"  [bold yellow]━━━ MEDIUM FINDINGS ({len(medium_findings)}) ━━━[/]"
        )
        for finding in medium_findings:
            style = "yellow"
            console.print(
                f"  {_CATEGORY_ICONS[RiskCategory.MEDIUM]} "
                f"[{style}][{finding.risk_score:.2f}][/] "
                f"{finding.vuln_type:20s} "
                f"[cyan]{finding.file}[/]:{finding.line_start}"
            )
        console.print()

    # ── Low findings (count only) ───────────────────────────
    low_findings = [
        f for f in report.findings if f.risk_category == RiskCategory.LOW
    ]
    if low_findings:
        console.print(
            f"  [dim]━━━ LOW FINDINGS: {len(low_findings)} "
            f"(tracked in backlog) ━━━[/]"
        )
        console.print()

    # ── No findings ─────────────────────────────────────────
    if not report.findings:
        console.print(
            Panel(
                "✅ No security findings detected. Great work!",
                border_style="green",
                expand=True,
            )
        )
        console.print()

    # ── PDF report path ─────────────────────────────────────
    if report.report_path:
        console.print(
            f"  📄 PDF Report: [bold cyan]{report.report_path}[/]"
        )
        console.print()

    # ── Footer ──────────────────────────────────────────────
    duration_s = report.scan_duration_ms / 1000
    console.print(
        f"  [dim]⏱️  Scan completed in {duration_s:.1f}s | "
        f"Raw: {summary.total_raw} → Deduped: {summary.after_dedup} | "
        f"Reduction: {_reduction_pct(summary.total_raw, summary.after_dedup)}[/]"
    )
    console.print()


def _reduction_pct(raw: int, deduped: int) -> str:
    """Calculate and format the deduplication reduction percentage."""
    if raw == 0:
        return "N/A"
    reduction = ((raw - deduped) / raw) * 100
    return f"{reduction:.0f}%"
