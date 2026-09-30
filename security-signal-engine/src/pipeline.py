"""
Scan pipeline orchestrator.

Chains all 6 pipeline stages end-to-end:
  1. Scanner Orchestration → List[RawFinding]
  2. Normalization → List[NormalizedFinding]
  3. Deduplication → List[DeduplicatedFinding]
  4. Risk Scoring → List[ScoredFinding]
  5. LLM Intelligence → List[EnrichedFinding] + executive_summary
  6. Report Generation → ScanReport + PDF

Each stage has a clearly defined input/output contract.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from src.config import AppSettings, get_settings
from src.dedup.engine import DeduplicationEngine
from src.llm.intelligence import LLMIntelligenceLayer
from src.models.schemas import (
    RiskCategory,
    ScanConfig,
    ScanReport,
    ScanSummary,
)
from src.normalization.engine import NormalizationEngine
from src.scanners.orchestrator import ScannerOrchestrator
from src.scanners.false_positive_filter import FalsePositiveFilter
from src.scoring.engine import RiskScoringEngine

logger = logging.getLogger(__name__)


class ScanPipeline:
    """
    End-to-end scan pipeline orchestrator.
    
    Manages the full lifecycle of a security scan from scanner
    invocation through to report generation.
    """

    def __init__(self, config: ScanConfig | None = None, settings: AppSettings | None = None):
        if settings is None:
            settings = get_settings()

        self.config = config or ScanConfig(
            scanners_enabled=settings.scanners_enabled,
            semgrep=settings.semgrep,
            llm=settings.llm,
            scoring=settings.scoring,
            fail_on=settings.fail_on,
            output_format=settings.output_format,
        )

        # Initialize pipeline stages
        self.scanner_orchestrator = ScannerOrchestrator(self.config)
        self.false_positive_filter = FalsePositiveFilter(
            similarity_threshold=self.config.fp_filter.similarity_threshold,
            enabled=self.config.fp_filter.enabled,
        )
        self.normalization_engine = NormalizationEngine()
        self.deduplication_engine = DeduplicationEngine()
        self.risk_scoring_engine = RiskScoringEngine(self.config.scoring)
        self.llm_intelligence = LLMIntelligenceLayer(self.config.llm)
        self.llm_intelligence.instruction = self.config.instruction

    def run(
        self,
        target: str,
        progress_callback=None,
        generate_pdf: bool = True,
    ) -> ScanReport:
        """
        Execute the full scan pipeline.
        
        Args:
            target: Path to the directory to scan.
            progress_callback: Optional callable(stage_name, status) for progress updates.
            
        Returns:
            Complete ScanReport with all enriched findings.
        """
        scan_id = str(uuid.uuid4())
        start_time = time.time()

        def _progress(stage: str, status: str = "running"):
            if progress_callback:
                progress_callback(stage, status)
            logger.info("Pipeline stage: %s [%s]", stage, status)

        # ── Stage 1: Scanner Orchestration ──────────────────
        _progress("Scanner Orchestration")
        self.normalization_engine.target_path = target
        raw_findings = self.scanner_orchestrator.run(target)
        total_raw = len(raw_findings)
        scanners_used = self.scanner_orchestrator.scanners_used_for_target(target)
        scanner_versions = self.scanner_orchestrator.scanner_versions_for_target(target)
        _progress("Scanner Orchestration", f"done ({total_raw} findings)")

        # ── Stage 1.5: False Positive Filtering ─────────────
        _progress("False Positive Filtering")
        filtered_findings = self.false_positive_filter.filter(raw_findings)
        fp_stats = self.false_positive_filter.stats
        _progress(
            "False Positive Filtering",
            f"done ({total_raw} → {len(filtered_findings)}, "
            f"-{fp_stats.removed_by_confidence} confidence, "
            f"-{fp_stats.removed_by_duplicate} dupes, "
            f"-{fp_stats.removed_by_known_fp} known_fp)"
        )

        # ── Stage 2: Normalization ──────────────────────────
        _progress("Normalization")
        normalized = self.normalization_engine.normalize(filtered_findings)
        _progress("Normalization", f"done ({len(normalized)} findings)")

        # ── Stage 3: Deduplication ──────────────────────────
        _progress("Deduplication")
        deduplicated = self.deduplication_engine.deduplicate(normalized)
        _progress("Deduplication", f"done ({len(deduplicated)} unique)")

        # ── Stage 4: Risk Scoring ───────────────────────────
        _progress("Risk Scoring")
        scored = self.risk_scoring_engine.score(deduplicated)
        _progress("Risk Scoring", "done")

        # ── Stage 5: LLM Intelligence ──────────────────────
        _progress("LLM Intelligence")
        enriched, executive_summary = self.llm_intelligence.enrich(
            scored, total_raw=total_raw, target=target
        )
        _progress("LLM Intelligence", "done")

        # ── Stage 6: Report Assembly ────────────────────────
        _progress("Report Generation")

        # Compute summary stats (with HIGH tier)
        critical = sum(1 for f in enriched if f.risk_category == RiskCategory.CRITICAL)
        high = sum(1 for f in enriched if f.risk_category == RiskCategory.HIGH)
        medium = sum(1 for f in enriched if f.risk_category == RiskCategory.MEDIUM)
        low = sum(1 for f in enriched if f.risk_category == RiskCategory.LOW)

        duration_ms = int((time.time() - start_time) * 1000)

        report = ScanReport(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=target,
            summary=ScanSummary(
                total_raw=total_raw,
                after_dedup=len(enriched),
                critical=critical,
                high=high,
                medium=medium,
                low=low,
            ),
            findings=enriched,
            executive_summary=executive_summary,
            scan_duration_ms=duration_ms,
            scanners_used=scanners_used,
            scanner_versions=scanner_versions,
        )

        # ── Generate PDF report ─────────────────────────────
        if generate_pdf:
            try:
                from src.reports.pdf_report import generate_pdf_report
                pdf_path = generate_pdf_report(report)
                report.report_path = pdf_path
                logger.info("PDF report saved to: %s", pdf_path)
            except Exception as e:
                logger.warning("PDF report generation failed: %s", e)

        _progress("Report Generation", "done")

        logger.info(
            "Pipeline complete: %d raw → %d deduped → "
            "%d CRITICAL / %d HIGH / %d MEDIUM / %d LOW in %dms",
            total_raw,
            len(enriched),
            critical,
            high,
            medium,
            low,
            duration_ms,
        )

        return report

    def should_fail(self, report: ScanReport) -> bool:
        """
        Check if the scan should trigger a CI/CD failure.
        
        Returns True if --fail-on threshold is met.
        """
        if not self.config.fail_on:
            return False

        fail_on = self.config.fail_on.upper()

        if fail_on == "CRITICAL" and report.summary.critical > 0:
            return True
        if fail_on == "HIGH" and (
            report.summary.critical > 0 or report.summary.high > 0
        ):
            return True
        if fail_on == "MEDIUM" and (
            report.summary.critical > 0
            or report.summary.high > 0
            or report.summary.medium > 0
        ):
            return True
        if fail_on == "LOW" and (
            report.summary.critical > 0
            or report.summary.high > 0
            or report.summary.medium > 0
            or report.summary.low > 0
        ):
            return True

        return False
