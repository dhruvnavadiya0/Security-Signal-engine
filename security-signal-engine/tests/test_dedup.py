"""
Tests for the deduplication engine.
"""

import pytest

from src.dedup.engine import DeduplicationEngine
from src.models.schemas import NormalizedFinding, Severity


def _make_finding(
    file: str = "app/routes/users.py",
    vuln_type: str = "SQL_INJECTION",
    line_start: int = 42,
    tool_source: str = "semgrep",
    confidence: float = 0.9,
    cwe_id: str | None = "CWE-89",
    severity: Severity = Severity.HIGH,
) -> NormalizedFinding:
    """Helper to create a normalized finding for testing."""
    return NormalizedFinding(
        file=file,
        line_start=line_start,
        severity=severity,
        vuln_type=vuln_type,
        description=f"Test finding: {vuln_type}",
        tool_source=tool_source,
        confidence=confidence,
        cwe_id=cwe_id,
        raw={},
    )


class TestDeduplicationEngine:
    """Tests for the DeduplicationEngine class."""

    def test_no_duplicates(self):
        """Findings with different files should not be deduplicated."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(file="a.py", line_start=10),
            _make_finding(file="b.py", line_start=10),
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 2

    def test_exact_duplicates_merged(self):
        """Identical findings from same tool should be merged."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(line_start=42, confidence=0.8),
            _make_finding(line_start=43, confidence=0.9),  # Within ±5 tolerance
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 1
        assert results[0].confidence == 0.9  # Highest confidence retained

    def test_line_tolerance(self):
        """Findings within ±5 lines should be deduplicated."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(line_start=40, confidence=0.7),
            _make_finding(line_start=44, confidence=0.9),  # Same bucket (40-44)
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 1

    def test_outside_line_tolerance(self):
        """Findings more than 5 lines apart should NOT be deduplicated."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(line_start=10, confidence=0.7, cwe_id=None),
            _make_finding(line_start=20, confidence=0.9, cwe_id=None),  # Different bucket
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 2

    def test_multi_tool_sources_merged(self):
        """When findings from different tools are merged, sources list includes both."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(tool_source="semgrep", confidence=0.8),
            _make_finding(tool_source="zap", confidence=0.7),
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 1
        assert set(results[0].sources) == {"semgrep", "zap"}

    def test_cwe_secondary_key(self):
        """Findings with matching CWE IDs should be considered duplicates."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(
                vuln_type="SQL_INJECTION",
                line_start=42,
                tool_source="semgrep",
                cwe_id="CWE-89",
            ),
            _make_finding(
                vuln_type="SQL_INJECTION",
                line_start=43,
                tool_source="zap",
                cwe_id="CWE-89",
            ),
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 1

    def test_empty_input(self):
        """Deduplicating an empty list returns empty."""
        engine = DeduplicationEngine()
        results = engine.deduplicate([])
        assert results == []

    def test_different_vuln_types_not_merged(self):
        """Findings with different vuln types at same line should not merge."""
        engine = DeduplicationEngine()
        findings = [
            _make_finding(vuln_type="SQL_INJECTION", line_start=42, cwe_id=None),
            _make_finding(vuln_type="XSS", line_start=42, cwe_id=None),
        ]
        results = engine.deduplicate(findings)
        assert len(results) == 2
