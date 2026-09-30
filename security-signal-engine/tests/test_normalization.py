"""
Tests for the normalization engine.
"""

import pytest

from src.models.schemas import NormalizedFinding, RawFinding, Severity
from src.normalization.engine import NormalizationEngine


@pytest.fixture
def sample_raw_findings() -> list[RawFinding]:
    """Create sample raw findings for testing."""
    return [
        RawFinding(
            tool_source="semgrep",
            file="app/routes/users.py",
            line_start=42,
            line_end=42,
            severity="ERROR",
            vuln_type="SQL_INJECTION",
            description="Possible SQL injection via string concatenation",
            rule_id="python.lang.security.audit.sqli",
            cwe_id="CWE-89",
            confidence=0.9,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            raw={"check_id": "python.lang.security.audit.sqli"},
        ),
        RawFinding(
            tool_source="semgrep",
            file="app/utils/render.py",
            line_start=15,
            severity="WARNING",
            vuln_type="XSS",
            description="Unescaped user input in template",
            rule_id="python.flask.security.xss",
            confidence=0.7,
            code_snippet="return render_template_string(user_input)",
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
            code_snippet='DB_PASSWORD = "admin123"',
            raw={},
        ),
    ]


class TestNormalizationEngine:
    """Tests for the NormalizationEngine class."""

    def test_normalize_maps_severities(self, sample_raw_findings):
        """Verify Semgrep severity mapping per PRD Table 5."""
        engine = NormalizationEngine()
        results = engine.normalize(sample_raw_findings)

        assert len(results) == 3
        assert results[0].severity == Severity.HIGH     # ERROR → HIGH
        assert results[1].severity == Severity.MEDIUM    # WARNING → MEDIUM
        assert results[2].severity == Severity.LOW       # INFO → LOW

    def test_normalize_assigns_uuids(self, sample_raw_findings):
        """Each normalized finding should have a unique UUID."""
        engine = NormalizationEngine()
        results = engine.normalize(sample_raw_findings)

        ids = [f.id for f in results]
        assert len(set(ids)) == len(ids)  # All unique

    def test_normalize_preserves_fields(self, sample_raw_findings):
        """Normalized findings should preserve key fields from raw input."""
        engine = NormalizationEngine()
        results = engine.normalize(sample_raw_findings)

        first = results[0]
        assert first.file == "app/routes/users.py"
        assert first.line_start == 42
        assert first.vuln_type == "SQL_INJECTION"
        assert first.tool_source == "semgrep"
        assert first.cwe_id == "CWE-89"
        assert first.confidence == 0.9

    def test_normalize_empty_list(self):
        """Normalizing an empty list should return an empty list."""
        engine = NormalizationEngine()
        results = engine.normalize([])
        assert results == []

    def test_normalize_unknown_severity(self):
        """Unknown severity should default to MEDIUM."""
        engine = NormalizationEngine()
        raw = RawFinding(
            tool_source="custom_tool",
            file="test.py",
            line_start=1,
            severity="UNKNOWN_SEV",
            confidence=0.5,
            raw={},
        )
        results = engine.normalize([raw])
        assert len(results) == 1
        assert results[0].severity == Severity.MEDIUM
