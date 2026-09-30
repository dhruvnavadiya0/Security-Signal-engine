"""
Tests for the risk scoring engine.
"""

import pytest

from src.models.schemas import (
    DeduplicatedFinding,
    RiskCategory,
    RiskPolicyConfig,
    Severity,
)
from src.scoring.engine import RiskScoringEngine


def _make_dedup_finding(
    file: str = "app/routes/users.py",
    vuln_type: str = "SQL_INJECTION",
    line_start: int = 42,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    sources: list[str] | None = None,
    code_snippet: str | None = None,
    description: str = "Test finding",
) -> DeduplicatedFinding:
    """Helper to create a deduplicated finding for testing."""
    return DeduplicatedFinding(
        file=file,
        line_start=line_start,
        severity=severity,
        vuln_type=vuln_type,
        description=description,
        confidence=confidence,
        sources=sources or ["semgrep"],
        code_snippet=code_snippet,
        raw={},
    )


class TestRiskScoringEngine:
    """Tests for the RiskScoringEngine class."""

    def test_high_severity_sql_injection(self):
        """HIGH + SQL_INJECTION should never fall below HIGH due to policy floor."""
        engine = RiskScoringEngine()
        finding = _make_dedup_finding(
            severity=Severity.HIGH,
            vuln_type="SQL_INJECTION",
            confidence=0.9,
        )
        results = engine.score([finding])
        assert len(results) == 1
        assert results[0].risk_score > 0.4
        assert results[0].risk_category in (RiskCategory.HIGH, RiskCategory.CRITICAL)
        assert results[0].category_source in ("vuln_floor", "score")

    def test_auth_context_multiplier(self):
        """Findings in auth-related files should get higher scores."""
        engine = RiskScoringEngine()
        normal = _make_dedup_finding(file="app/utils/helpers.py")
        auth = _make_dedup_finding(file="app/auth/login.py")

        results_normal = engine.score([normal])
        results_auth = engine.score([auth])

        assert results_auth[0].risk_score > results_normal[0].risk_score

    def test_multi_tool_bonus(self):
        """Findings from multiple tools should get a bonus."""
        engine = RiskScoringEngine()
        single = _make_dedup_finding(sources=["semgrep"])
        multi = _make_dedup_finding(sources=["semgrep", "zap"])

        results_single = engine.score([single])
        results_multi = engine.score([multi])

        assert results_multi[0].risk_score > results_single[0].risk_score

    def test_risk_categories(self):
        """Verify risk category assignment thresholds."""
        engine = RiskScoringEngine()

        # Low severity, low confidence → LOW
        low = _make_dedup_finding(
            severity=Severity.LOW,
            vuln_type="UNKNOWN",
            confidence=0.3,
        )
        results = engine.score([low])
        assert results[0].risk_category == RiskCategory.LOW

    def test_sorted_by_score_descending(self):
        """Results should be sorted by risk score, highest first."""
        engine = RiskScoringEngine()
        findings = [
            _make_dedup_finding(severity=Severity.LOW, confidence=0.3),
            _make_dedup_finding(severity=Severity.HIGH, confidence=0.9),
            _make_dedup_finding(severity=Severity.MEDIUM, confidence=0.6),
        ]
        results = engine.score(findings)
        scores = [r.risk_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_confidence_multiplier(self):
        """Lower confidence should reduce the final score."""
        engine = RiskScoringEngine()
        high_conf = _make_dedup_finding(confidence=1.0)
        low_conf = _make_dedup_finding(confidence=0.3)

        results_high = engine.score([high_conf])
        results_low = engine.score([low_conf])

        assert results_high[0].risk_score > results_low[0].risk_score

    def test_consistency_lock_keeps_previous_category(self, tmp_path):
        """Same fingerprint should keep historical category when downgrade is not allowed."""
        cache_path = tmp_path / "risk_cache.json"
        policy = RiskPolicyConfig(
            consistency_cache_path=str(cache_path),
            allow_category_downgrade=False,
        )
        engine = RiskScoringEngine(policy)

        high_first = _make_dedup_finding(
            file="app/auth/login.py",
            vuln_type="XSS",
            confidence=1.0,
            description="XSS in auth handler",
            severity=Severity.HIGH,
        )
        result_first = engine.score([high_first])[0]
        assert result_first.risk_category in (RiskCategory.HIGH, RiskCategory.CRITICAL)

        # New engine instance simulates a separate report run.
        engine_second_run = RiskScoringEngine(policy)
        lower_score_same_fingerprint = _make_dedup_finding(
            file="app/auth/login.py",
            vuln_type="XSS",
            confidence=0.1,
            description="XSS in auth handler",
            severity=Severity.LOW,
        )
        result_second = engine_second_run.score([lower_score_same_fingerprint])[0]
        assert result_second.risk_category == result_first.risk_category
        assert result_second.category_source == "consistency_cache"

    def test_consistency_lock_can_downgrade_when_enabled(self, tmp_path):
        """If downgrade is allowed, category can move down in later runs."""
        cache_path = tmp_path / "risk_cache_allow_down.json"
        locked_policy = RiskPolicyConfig(
            consistency_cache_path=str(cache_path),
            allow_category_downgrade=True,
        )
        engine = RiskScoringEngine(locked_policy)

        first = _make_dedup_finding(
            file="app/routes/public.py",
            vuln_type="OPEN_REDIRECT",
            severity=Severity.HIGH,
            confidence=1.0,
        )
        _ = engine.score([first])[0]

        second_engine = RiskScoringEngine(locked_policy)
        second = _make_dedup_finding(
            file="app/routes/public.py",
            vuln_type="OPEN_REDIRECT",
            severity=Severity.LOW,
            confidence=0.1,
        )
        result = second_engine.score([second])[0]
        assert result.category_source in ("score", "vuln_floor")

    def test_empty_input(self):
        """Scoring an empty list returns empty."""
        engine = RiskScoringEngine()
        results = engine.score([])
        assert results == []

    def test_score_capped_at_one(self):
        """Risk score should never exceed 1.0."""
        engine = RiskScoringEngine()
        # Maximum everything
        finding = _make_dedup_finding(
            severity=Severity.CRITICAL,
            vuln_type="RCE",
            confidence=1.0,
            sources=["semgrep", "zap"],
            file="admin/auth/login.py",
            code_snippet="@app.route('/admin') def handler(request):",
        )
        results = engine.score([finding])
        assert results[0].risk_score <= 1.0
