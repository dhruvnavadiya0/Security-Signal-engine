"""
LLM intelligence layer.

Enriches scored findings with plain-language explanations, fix
suggestions, and business impact assessments using a local LLM
(Ollama + DeepSeek-Coder-V2 16B by default). Falls back to deterministic templates
when the LLM is unavailable.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import logging

from src.models.schemas import (
    EnrichedFinding,
    LLMConfig,
    RiskCategory,
    ScoredFinding,
)
from src.llm.client import OllamaClient
from src.llm.fallback import (
    generate_fallback_executive_summary,
    get_fallback_analysis,
)
from src.llm.prompts import build_executive_summary_prompt, build_finding_prompt

logger = logging.getLogger(__name__)


def _generate_title(finding: ScoredFinding) -> str:
    """Generate a human-readable title for a finding."""
    vuln_display = finding.vuln_type.replace("_", " ").title()
    file_short = finding.file.split("/")[-1] if "/" in finding.file else finding.file
    return f"{vuln_display} in {file_short}:{finding.line_start}"


class LLMIntelligenceLayer:
    """
    LLM-based intelligence layer for enriching security findings.
    
    Operates on structured, validated data only. Never used for raw
    detection or pattern matching. Its role is to translate
    machine-readable findings into human-understandable output.
    
    Falls back to rule-based templates if Ollama is unavailable or
    LLM output fails validation (PRD Section 5.5.4).
    """

    def __init__(self, config: LLMConfig | None = None):
        self.config = config or LLMConfig()
        self.client = OllamaClient(self.config)
        self._llm_available: bool | None = None
        self._llm_disabled_for_run = False

    @property
    def llm_available(self) -> bool:
        """Check and cache whether the LLM is available."""
        if self._llm_available is None:
            if not self.config.enabled:
                self._llm_available = False
                logger.info("LLM enrichment is disabled by configuration")
            else:
                self._llm_available = self.client.is_available()
                if self._llm_available:
                    logger.info("LLM (Ollama) is available — using AI-powered analysis")
                else:
                    logger.info(
                        "LLM (Ollama) is not available — falling back to rule-based templates"
                    )
        return self._llm_available

    def enrich(
        self,
        findings: list[ScoredFinding],
        total_raw: int = 0,
        target: str = "",
    ) -> tuple[list[EnrichedFinding], str]:
        """
        Enrich scored findings with LLM-generated or fallback analysis.
        
        Args:
            findings: Scored findings to enrich.
            total_raw: Total raw finding count (for executive summary).
            target: Scan target path (for executive summary).
            
        Returns:
            Tuple of (enriched findings, executive summary).
        """
        if not findings:
            return [], self._generate_executive_summary([], total_raw, target)

        # A slow or unhealthy local model should not multiply scan latency.
        self._llm_disabled_for_run = False

        # Process findings sequentially to avoid overwhelming the local Ollama instance
        # Concurrent LLM generation causes massive delays per request and leads to timeouts
        max_workers = 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            analyses = list(executor.map(self._analyze_finding, findings))

        enriched: list[EnrichedFinding] = []
        for finding, analysis in zip(findings, analyses):
            enriched_finding = EnrichedFinding(
                id=finding.id,
                title=_generate_title(finding),
                file=finding.file,
                line_start=finding.line_start,
                line_end=finding.line_end,
                severity=finding.severity,
                vuln_type=finding.vuln_type,
                description=finding.description,
                rule_id=finding.rule_id,
                confidence=finding.confidence,
                cwe_id=finding.cwe_id,
                cvss_score=finding.cvss_score,
                code_snippet=finding.code_snippet,
                sources=finding.sources,
                risk_score=finding.risk_score,
                risk_category=finding.risk_category,
                category_source=finding.category_source,
                category_reason=finding.category_reason,
                llm_explanation=analysis.get("explanation", ""),
                fix_suggestion=analysis.get("fix_suggestion", ""),
                business_impact=analysis.get("business_impact", ""),
                attack_path=analysis.get("attack_path", ""),
                next_test=analysis.get("next_test", ""),
                raw=finding.raw,
            )
            enriched.append(enriched_finding)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            findings=enriched,
            total_raw=total_raw,
            target=target,
        )

        return enriched, executive_summary

    def _analyze_finding(self, finding: ScoredFinding) -> dict[str, str]:
        """Analyze a single finding using LLM or context-aware fallback."""
        # Always compute the rule-based fix first — it's used in both paths:
        # 1. Passed to the LLM prompt so it can differentiate its output
        # 2. Shown directly in the report as the "Rule-Based" recommendation
        rule_based = get_fallback_analysis(
            finding.vuln_type,
            description=finding.description,
            code_snippet=finding.code_snippet or "",
            file_path=finding.file,
            cwe_id=finding.cwe_id or "",
        )
        rule_based_fix = rule_based.get("fix_suggestion", "")

        if finding.vuln_type == "SCAN_INCOMPLETE":
            return {
                "explanation": finding.description,
                "fix_suggestion": "Verify DNS, protocol, port, TLS, firewall, and application availability, then rerun the scan.",
                "business_impact": "No security conclusion can be made until the target is reachable and the assessment completes.",
                "attack_path": "UNKNOWN: target connectivity failed before reconnaissance.",
                "next_test": "Run a safe connectivity check against the authorized target and stop until it responds reliably.",
            }

        if self.llm_available and not self._llm_disabled_for_run:
            result = self._llm_analyze(finding, rule_based_fix=rule_based_fix)
            if result:
                return result
            self._llm_disabled_for_run = True
            logger.warning(
                "LLM analysis failed for %s:%d — using fallback for the rest of this scan",
                finding.file,
                finding.line_start,
            )

        # Keep the deterministic remediation in the structured finding so
        # JSON and SARIF consumers receive a useful fix without an LLM.
        return {
            "explanation": rule_based.get("explanation", ""),
            "fix_suggestion": rule_based_fix,
            "business_impact": rule_based.get("business_impact", ""),
            "attack_path": "UNKNOWN: deterministic fallback has no runtime proof.",
            "next_test": "Run one authorized, read-only validation test and stop if it changes state or exposes real data.",
        }

    def _llm_analyze(
        self,
        finding: ScoredFinding,
        rule_based_fix: str = "",
    ) -> dict[str, str] | None:
        """Use the LLM to analyze a finding. Returns None on failure."""
        prompt = build_finding_prompt(
            file=finding.file,
            line_start=finding.line_start,
            vuln_type=finding.vuln_type,
            severity=finding.severity.value,
            risk_category=finding.risk_category.value,
            risk_score=finding.risk_score,
            description=finding.description,
            code_snippet=finding.code_snippet,
            cwe_id=finding.cwe_id,
            rule_based_fix=rule_based_fix,
            instruction=getattr(self, "instruction", ""),
        )

        result = self.client.generate_json(prompt)
        if result is None:
            return None

        # Validate required fields
        required_fields = {"explanation", "fix_suggestion", "business_impact"}
        if not required_fields.issubset(result.keys()):
            logger.warning("LLM output missing required fields: %s", result.keys())
            return None

        return {
            "explanation": str(result["explanation"]),
            "fix_suggestion": str(result["fix_suggestion"]),
            "business_impact": str(result["business_impact"]),
            "attack_path": str(result.get("attack_path", "UNKNOWN")),
            "next_test": str(result.get("next_test", "Use an authorized, read-only validation test.")),
        }

    def _generate_executive_summary(
        self,
        findings: list[EnrichedFinding],
        total_raw: int,
        target: str,
    ) -> str:
        """Generate an executive summary of the scan."""
        critical = sum(1 for f in findings if f.risk_category == RiskCategory.CRITICAL)
        high = sum(1 for f in findings if f.risk_category == RiskCategory.HIGH)
        medium = sum(1 for f in findings if f.risk_category == RiskCategory.MEDIUM)
        low = sum(1 for f in findings if f.risk_category == RiskCategory.LOW)
        after_dedup = len(findings)

        if self.llm_available and not self._llm_disabled_for_run:
            # Build top findings summary — include both CRITICAL and HIGH
            top = [
                f for f in findings
                if f.risk_category in (RiskCategory.CRITICAL, RiskCategory.HIGH)
            ][:5]
            top_text = "\n".join(
                f"- [{f.risk_category.value}] {f.title}: {f.description[:100]}" for f in top
            ) or "No critical or high findings."

            prompt = build_executive_summary_prompt(
                total_raw=total_raw,
                after_dedup=after_dedup,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                target=target,
                top_findings=top_text,
            )

            result = self.client.generate(prompt)
            if result:
                return result.strip()

        # Fallback
        return generate_fallback_executive_summary(
            total_raw=total_raw,
            after_dedup=after_dedup,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            target=target,
        )
