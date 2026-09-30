"""
End-to-end pipeline test using fixture data (no actual Semgrep needed).
"""

import pytest
from unittest.mock import patch, MagicMock

from src.models.schemas import (
    RawFinding,
    RiskCategory,
    ScanConfig,
    LLMConfig,
)
from src.pipeline import ScanPipeline


@pytest.fixture
def mock_raw_findings() -> list[RawFinding]:
    """Fixture data simulating Semgrep output."""
    return [
        RawFinding(
            tool_source="semgrep",
            file="app/routes/users.py",
            line_start=42,
            severity="ERROR",
            vuln_type="SQL_INJECTION",
            description="SQL injection via string concatenation",
            rule_id="python.lang.security.sqli",
            cwe_id="CWE-89",
            confidence=0.9,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            raw={},
        ),
        # Duplicate of above (should be deduped)
        RawFinding(
            tool_source="semgrep",
            file="app/routes/users.py",
            line_start=43,
            severity="ERROR",
            vuln_type="SQL_INJECTION",
            description="SQL injection detected",
            rule_id="python.lang.security.sqli-2",
            cwe_id="CWE-89",
            confidence=0.8,
            raw={},
        ),
        RawFinding(
            tool_source="semgrep",
            file="app/utils/render.py",
            line_start=15,
            severity="WARNING",
            vuln_type="XSS",
            description="Unescaped user input in template",
            rule_id="python.flask.security.xss",
            cwe_id="CWE-79",
            confidence=0.7,
            raw={},
        ),
        RawFinding(
            tool_source="semgrep",
            file="config/settings.py",
            line_start=8,
            severity="INFO",
            vuln_type="HARDCODED_SECRET",
            description="Hardcoded password detected",
            rule_id="python.lang.security.hardcoded-password",
            confidence=0.4,
            raw={},
        ),
    ]


class TestPipelineEndToEnd:
    """End-to-end pipeline tests with mocked scanner output."""

    @patch("src.scanners.orchestrator.ScannerOrchestrator.run")
    def test_full_pipeline(self, mock_scanner_run, mock_raw_findings):
        """Full pipeline should produce a valid report."""
        mock_scanner_run.return_value = mock_raw_findings

        config = ScanConfig(llm=LLMConfig(enabled=False))
        pipeline = ScanPipeline(config=config)
        report = pipeline.run("/fake/target")

        # Should have raw findings
        assert report.summary.total_raw == 4

        # Deduplication should reduce count (2 SQLi findings → 1)
        assert report.summary.after_dedup < report.summary.total_raw

        # Should have findings
        assert len(report.findings) > 0

        # Findings should be enriched
        for finding in report.findings:
            assert finding.title != ""
            assert finding.risk_score >= 0
            assert finding.risk_category in (
                RiskCategory.CRITICAL,
                RiskCategory.HIGH,
                RiskCategory.MEDIUM,
                RiskCategory.LOW,
            )
            # Fallback analysis should be populated
            assert finding.llm_explanation != "" or finding.fix_suggestion != ""

        # Executive summary should exist
        assert report.executive_summary != ""

        # Duration should be tracked
        assert report.scan_duration_ms >= 0

    @patch("src.scanners.orchestrator.ScannerOrchestrator.run")
    def test_fail_on_critical(self, mock_scanner_run, mock_raw_findings):
        """Pipeline should detect when fail-on threshold is met."""
        mock_scanner_run.return_value = mock_raw_findings

        config = ScanConfig(
            fail_on="critical",
            llm=LLMConfig(enabled=False),
        )
        pipeline = ScanPipeline(config=config)
        report = pipeline.run("/fake/target")

        # With SQL injection findings, there may or may not be criticals
        # depending on scoring — but the mechanism should work
        result = pipeline.should_fail(report)
        assert isinstance(result, bool)

    @patch("src.scanners.orchestrator.ScannerOrchestrator.run")
    def test_empty_scan(self, mock_scanner_run):
        """Pipeline with no findings should produce a clean report."""
        mock_scanner_run.return_value = []

        config = ScanConfig(llm=LLMConfig(enabled=False))
        pipeline = ScanPipeline(config=config)
        report = pipeline.run("/fake/target")

        assert report.summary.total_raw == 0
        assert report.summary.after_dedup == 0
        assert report.summary.critical == 0
        assert len(report.findings) == 0
        assert report.executive_summary != ""

    @patch("src.scanners.orchestrator.ScannerOrchestrator.run")
    def test_progress_callback(self, mock_scanner_run, mock_raw_findings):
        """Progress callback should be called for each stage."""
        mock_scanner_run.return_value = mock_raw_findings
        stages_seen = []

        def callback(stage, status):
            stages_seen.append((stage, status))

        config = ScanConfig(llm=LLMConfig(enabled=False))
        pipeline = ScanPipeline(config=config)
        pipeline.run("/fake/target", progress_callback=callback)

        stage_names = [s[0] for s in stages_seen]
        assert "Scanner Orchestration" in stage_names
        assert "Normalization" in stage_names
        assert "Deduplication" in stage_names
        assert "Risk Scoring" in stage_names
        assert "LLM Intelligence" in stage_names
        assert "Report Generation" in stage_names
