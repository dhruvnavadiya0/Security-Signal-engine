"""
Tests for the LLM intelligence layer (fallback path).
"""

import pytest

from src.llm.fallback import (
    _VULN_KNOWLEDGE,
    generate_fallback_executive_summary,
    get_fallback_analysis,
)
from src.llm.intelligence import LLMIntelligenceLayer, _generate_title
from src.llm.prompts import build_finding_prompt
from src.models.schemas import (
    EnrichedFinding,
    LLMConfig,
    RiskCategory,
    ScoredFinding,
    Severity,
)


def _make_scored_finding(
    vuln_type: str = "SQL_INJECTION",
    file: str = "app/routes/users.py",
    line_start: int = 42,
    risk_score: float = 0.85,
    risk_category: RiskCategory = RiskCategory.CRITICAL,
    description: str = "Test SQL injection finding",
    code_snippet: str | None = None,
) -> ScoredFinding:
    """Helper to create a scored finding for testing."""
    return ScoredFinding(
        id="test-id-123",
        file=file,
        line_start=line_start,
        severity=Severity.HIGH,
        vuln_type=vuln_type,
        description=description,
        confidence=0.9,
        sources=["semgrep"],
        risk_score=risk_score,
        risk_category=risk_category,
        code_snippet=code_snippet,
        raw={},
    )


class TestFallbackTemplates:
    """Tests for deterministic fallback templates."""

    def test_known_vuln_types_have_templates(self):
        """All common vuln types should have fallback templates."""
        expected_types = [
            "SQL_INJECTION", "XSS", "SSRF", "RCE", "HARDCODED_SECRET",
            "INSECURE_DESERIALIZATION", "PATH_TRAVERSAL", "MISSING_AUTH",
            "IDOR", "OPEN_REDIRECT", "INSECURE_CRYPTO",
        ]
        for vtype in expected_types:
            result = get_fallback_analysis(vtype)
            assert "explanation" in result
            assert "fix_suggestion" in result
            assert "business_impact" in result
            assert len(result["explanation"]) > 20
            assert len(result["fix_suggestion"]) > 20

    def test_unknown_vuln_type_returns_default(self):
        """Unknown vuln types should return a generic fallback."""
        result = get_fallback_analysis("TOTALLY_UNKNOWN_TYPE")
        assert "explanation" in result
        assert "fix_suggestion" in result
        assert "business_impact" in result

    def test_context_aware_fix_selection(self):
        """Different code snippets for the same vuln_type should produce different fixes."""
        sqlite_result = get_fallback_analysis(
            "SQL_INJECTION",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            description="SQL injection via sqlite3 cursor",
        )
        django_result = get_fallback_analysis(
            "SQL_INJECTION",
            code_snippet="User.objects.raw('SELECT * FROM auth_user WHERE id = %s' % uid)",
            description="SQL injection via Django raw query",
        )
        # They should pick different fix patterns
        assert "sqlite" not in django_result["fix_suggestion"].lower() or \
               "django" in django_result["fix_suggestion"].lower()

    def test_context_aware_asset_detection(self):
        """Different descriptions should produce different impact statements."""
        env_result = get_fallback_analysis(
            "INFORMATION_DISCLOSURE",
            description=".env file is publicly accessible",
            file_path="/app/.env",
        )
        git_result = get_fallback_analysis(
            "INFORMATION_DISCLOSURE",
            description=".git/config is publicly accessible",
            file_path="/app/.git/config",
        )
        # The impact statements should mention different assets
        assert env_result["business_impact"] != git_result["business_impact"]

    def test_findings_same_type_different_context_produce_unique_output(self):
        """Two findings of the same vuln_type but different context must not be identical."""
        result_a = get_fallback_analysis(
            "INFORMATION_DISCLOSURE",
            description="Server header leaks Apache version",
            code_snippet="Server: Apache/2.4.41",
        )
        result_b = get_fallback_analysis(
            "INFORMATION_DISCLOSURE",
            description="Database backup file is publicly accessible",
            file_path="backup.sql",
        )
        # At least the explanation should differ (because it includes description context)
        assert result_a["explanation"] != result_b["explanation"]

    def test_executive_summary_with_criticals(self):
        """Executive summary should mention critical findings."""
        summary = generate_fallback_executive_summary(
            total_raw=100,
            after_dedup=25,
            critical=3,
            high=2,
            medium=10,
            low=12,
            target="/my/project",
        )
        assert "CRITICAL" in summary
        assert "100" in summary
        assert "25" in summary

    def test_executive_summary_no_findings(self):
        """Executive summary with no findings should be positive."""
        summary = generate_fallback_executive_summary(
            total_raw=0, after_dedup=0, critical=0, high=0, medium=0, low=0,
            target="/my/project",
        )
        assert "no significant" in summary.lower() or "No significant" in summary


class TestLLMIntelligenceLayer:
    """Tests for LLM intelligence layer (with LLM disabled)."""

    def test_enrich_with_llm_disabled(self):
        """When LLM is disabled, should use fallback templates."""
        config = LLMConfig(enabled=False)
        layer = LLMIntelligenceLayer(config=config)
        findings = [_make_scored_finding()]

        enriched, summary = layer.enrich(findings, total_raw=10, target="/test")

        assert len(enriched) == 1
        assert enriched[0].llm_explanation != ""
        assert enriched[0].fix_suggestion != ""
        assert enriched[0].business_impact != ""
        assert summary != ""

    def test_incomplete_scan_skips_llm(self, monkeypatch):
        """Connectivity failures should use immediate local guidance."""
        config = LLMConfig(enabled=True)
        layer = LLMIntelligenceLayer(config=config)
        layer._llm_available = True
        monkeypatch.setattr(layer.client, "generate_json", lambda prompt: (_ for _ in ()).throw(AssertionError("LLM called")))
        finding = _make_scored_finding(
            vuln_type="SCAN_INCOMPLETE",
            risk_category=RiskCategory.HIGH,
            description="Target timed out before assessment.",
        )

        enriched, _ = layer.enrich([finding])

        assert enriched[0].next_test.startswith("Run a safe connectivity check")

    def test_title_generation(self):
        """Generated titles should include vuln type and file."""
        finding = _make_scored_finding()
        title = _generate_title(finding)
        assert "Sql Injection" in title
        assert "users.py" in title
        assert "42" in title

    def test_enrich_preserves_risk_score(self):
        """Enrichment should preserve the original risk score."""
        config = LLMConfig(enabled=False)
        layer = LLMIntelligenceLayer(config=config)
        finding = _make_scored_finding(risk_score=0.85)

        enriched, _ = layer.enrich([finding])
        assert enriched[0].risk_score == 0.85
        assert enriched[0].risk_category == RiskCategory.CRITICAL

    def test_enrich_produces_unique_text_per_finding(self):
        """Enrichment of different findings should NOT produce identical text."""
        config = LLMConfig(enabled=False)
        layer = LLMIntelligenceLayer(config=config)
        finding_a = _make_scored_finding(
            vuln_type="INFORMATION_DISCLOSURE",
            file="/.env",
            description=".env file exposed with DB_PASSWORD=admin123",
        )
        finding_b = _make_scored_finding(
            vuln_type="INFORMATION_DISCLOSURE",
            file="/.git/config",
            description="Git config exposed with repository URL",
        )

        enriched, _ = layer.enrich([finding_a, finding_b])
        assert enriched[0].llm_explanation != enriched[1].llm_explanation

    def test_llm_failure_switches_remaining_findings_to_fallback(self, monkeypatch):
        """A failed model request must not delay every remaining finding."""
        layer = LLMIntelligenceLayer(LLMConfig(enabled=True, timeout=1))
        layer._llm_available = True
        calls = {"count": 0}

        def failed_generation(prompt):
            calls["count"] += 1
            return None

        monkeypatch.setattr(layer.client, "generate_json", failed_generation)
        enriched, _ = layer.enrich(
            [_make_scored_finding(), _make_scored_finding(file="other.py")],
            total_raw=2,
        )

        assert calls["count"] == 1
        assert all(finding.fix_suggestion for finding in enriched)

    def test_finding_prompt_pushes_practical_remediation(self):
        """The LLM prompt should push concrete, feasible fixes over generic advice."""
        prompt = build_finding_prompt(
            file="app.py",
            line_start=42,
            vuln_type="SQL_INJECTION",
            severity="HIGH",
            risk_category="CRITICAL",
            risk_score=0.91,
            description="Test finding",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            cwe_id="CWE-89",
        )

        assert "realistic, and specific to this exact codebase" in prompt
        assert "smallest safe code change" in prompt
        assert "Avoid architecture rewrites" in prompt
        assert "Avoid generic advice" in prompt
