"""
Risk scoring engine.

Applies a dynamic, context-aware scoring model that goes beyond static
CVSS scores to reflect real-world exploitability in a given codebase.

Formula (PRD Section 5.4.1):
    Risk Score = (Base Severity Weight × 0.4)
               + (Context Multiplier × 0.3)
               + (Vuln Type Weight × 0.2)
               + (Multi-Tool Confirmation Bonus × 0.1)
    Final Score = Risk Score × max(confidence, CONFIDENCE_FLOOR)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from src.models.schemas import (
    DeduplicatedFinding,
    RiskCategory,
    RiskPolicyConfig,
    ScoredFinding,
    Severity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights from PRD Tables 6 & 7
# ---------------------------------------------------------------------------

BASE_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.0,
}

VULN_TYPE_WEIGHTS: dict[str, float] = {
    "SQL_INJECTION": 1.0,
    "RCE": 1.0,
    "COMMAND_INJECTION": 1.0,
    "SSRF": 0.9,
    "XSS": 0.85,
    "HARDCODED_SECRET": 0.85,
    "PATH_TRAVERSAL": 0.8,
    "IDOR": 0.75,
    "INSECURE_DESERIALIZATION": 0.85,
    "XXE": 0.8,
    "OPEN_REDIRECT": 0.5,
    "INSECURE_CRYPTO": 0.6,
    "WEAK_RANDOMNESS": 0.75,
    "XPATH_INJECTION": 0.85,
    "LDAP_INJECTION": 0.85,
    "TRUST_BOUNDARY_VIOLATION": 0.70,
    "MISSING_AUTH": 0.9,
    # URL scanner types
    "MISSING_SECURITY_HEADER": 0.3,
    "CLICKJACKING": 0.55,
    "INFORMATION_DISCLOSURE": 0.5,
    "INSECURE_TRANSPORT": 0.9,
    "INSECURE_COOKIE": 0.55,
    "CORS_MISCONFIGURATION": 0.7,
    "SCAN_INCOMPLETE": 0.9,
}

DEFAULT_VULN_TYPE_WEIGHT = 0.5

# Context patterns for multiplier calculation
AUTH_PATTERNS = re.compile(
    r"(auth|login|session|token|password|credential|jwt|oauth)",
    re.IGNORECASE,
)
PUBLIC_ENDPOINT_PATTERNS = re.compile(
    r"(route|endpoint|handler|controller|view|api|request|response|app\.get|app\.post|@app\.|@router\.)",
    re.IGNORECASE,
)
ADMIN_PATTERNS = re.compile(
    r"(admin|role|permission|rbac|privilege|superuser|is_staff)",
    re.IGNORECASE,
)

_RISK_ORDER: dict[RiskCategory, int] = {
    RiskCategory.LOW: 0,
    RiskCategory.MEDIUM: 1,
    RiskCategory.HIGH: 2,
    RiskCategory.CRITICAL: 3,
}


def _to_risk_category(value: str) -> RiskCategory | None:
    """Safely convert string value to RiskCategory."""
    try:
        return RiskCategory(value.upper())
    except Exception:
        return None


def _compute_context_multiplier(finding: DeduplicatedFinding) -> float:
    """
    Compute context multiplier based on file path and code patterns.
    
    From PRD Table 6:
    - +0.3 if file path contains auth/, login, session, token
    - +0.2 if file exposes HTTP route handling user input
    - +0.25 if admin, role, permission patterns found
    """
    multiplier = 0.0
    search_text = f"{finding.file} {finding.code_snippet or ''} {finding.description}"

    if AUTH_PATTERNS.search(search_text):
        multiplier += 0.3

    if PUBLIC_ENDPOINT_PATTERNS.search(search_text):
        multiplier += 0.2

    if ADMIN_PATTERNS.search(search_text):
        multiplier += 0.25

    # Cap at 1.0
    return min(multiplier, 1.0)


def _compute_multi_tool_bonus(finding: DeduplicatedFinding) -> float:
    """Return 1.0 if detected by 2+ scanners, else 0.0."""
    return 1.0 if len(finding.sources) >= 2 else 0.0


def _confidence_factor(confidence: float) -> float:
    """
    Convert confidence (0-1) into a mild score multiplier.

    Confidence should reduce risk slightly, not suppress findings entirely.
    We therefore scale into [0.8, 1.0] and multiply by this factor.
    """
    clamped = max(0.0, min(confidence, 1.0))
    return 0.8 + (0.2 * clamped)


def _categorize_risk(score: float, policy: RiskPolicyConfig) -> RiskCategory:
    """Map risk score to risk category (with HIGH tier)."""
    if score >= policy.critical_threshold:
        return RiskCategory.CRITICAL
    if score >= policy.high_threshold:
        return RiskCategory.HIGH
    if score >= policy.medium_threshold:
        return RiskCategory.MEDIUM
    return RiskCategory.LOW


def _finding_fingerprint(finding: DeduplicatedFinding) -> str:
    """Build a stable key used to lock category consistency across runs."""
    filename = Path(finding.file).name.lower()
    rule = (finding.rule_id or "").strip().lower()
    cwe = (finding.cwe_id or "").strip().upper()
    vuln = finding.vuln_type.strip().upper()
    return "|".join([vuln, rule, cwe, filename])


class RiskScoringEngine:
    """
    Context-aware risk scoring engine.
    
    Computes a dynamic risk score for each finding based on severity,
    code context, vulnerability type, and multi-tool confirmation.
    """

    def __init__(self, policy: RiskPolicyConfig | None = None):
        self.policy = policy or RiskPolicyConfig()
        self._cache: dict[str, str] = {}
        self._cache_dirty = False
        self._cache_path = Path(self.policy.consistency_cache_path)
        self._load_cache()

    def _load_cache(self) -> None:
        """Load persisted category consistency cache from disk."""
        if not self.policy.consistency_lock_enabled:
            return
        try:
            if not self._cache_path.exists():
                return
            with self._cache_path.open("r", encoding="utf-8") as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                self._cache = {str(k): str(v) for k, v in payload.items()}
        except Exception as e:
            logger.warning("Unable to load risk cache %s: %s", self._cache_path, e)

    def _save_cache(self) -> None:
        """Persist category consistency cache to disk."""
        if not self.policy.consistency_lock_enabled or not self._cache_dirty:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open("w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2, sort_keys=True)
            self._cache_dirty = False
        except Exception as e:
            logger.warning("Unable to save risk cache %s: %s", self._cache_path, e)

    def _apply_vuln_floor(
        self,
        finding: DeduplicatedFinding,
        category: RiskCategory,
    ) -> tuple[RiskCategory, str, str]:
        """Enforce minimum category by vulnerability type."""
        configured_floor = self.policy.min_category_by_vuln_type.get(
            finding.vuln_type.upper()
        )
        if configured_floor is None:
            return category, "score", "score-threshold"

        if _RISK_ORDER[category] >= _RISK_ORDER[configured_floor]:
            return category, "score", "score-threshold"

        return (
            configured_floor,
            "vuln_floor",
            f"minimum floor for {finding.vuln_type}",
        )

    def _apply_consistency_lock(
        self,
        fingerprint: str,
        category: RiskCategory,
        default_source: str,
        default_reason: str,
    ) -> tuple[RiskCategory, str, str]:
        """Keep category stable between scans unless explicit downgrade is allowed."""
        if not self.policy.consistency_lock_enabled:
            return category, default_source, default_reason

        cached_category = _to_risk_category(self._cache.get(fingerprint, ""))
        if cached_category is None:
            self._cache[fingerprint] = category.value
            self._cache_dirty = True
            return category, default_source, default_reason

        # Always allow escalation.
        if _RISK_ORDER[category] > _RISK_ORDER[cached_category]:
            self._cache[fingerprint] = category.value
            self._cache_dirty = True
            return category, default_source, default_reason

        # Downgrade policy.
        if _RISK_ORDER[category] < _RISK_ORDER[cached_category]:
            if self.policy.allow_category_downgrade:
                self._cache[fingerprint] = category.value
                self._cache_dirty = True
                return category, default_source, default_reason
            return (
                cached_category,
                "consistency_cache",
                f"locked to historical category {cached_category.value}",
            )

        return category, default_source, default_reason

    def score(self, findings: list[DeduplicatedFinding]) -> list[ScoredFinding]:
        """
        Score a list of deduplicated findings.
        
        Args:
            findings: Deduplicated findings to score.
            
        Returns:
            Scored findings with risk_score and risk_category populated.
        """
        scored: list[ScoredFinding] = []

        for finding in findings:
            try:
                # Component scores
                base = BASE_SEVERITY_WEIGHTS.get(finding.severity, 0.5)
                context = _compute_context_multiplier(finding)
                vuln_weight = VULN_TYPE_WEIGHTS.get(
                    finding.vuln_type, DEFAULT_VULN_TYPE_WEIGHT
                )
                multi_tool = _compute_multi_tool_bonus(finding)

                # Weighted combination
                raw_score = (
                    (base * 0.4)
                    + (context * 0.3)
                    + (vuln_weight * 0.2)
                    + (multi_tool * 0.1)
                )

                # Apply confidence as a mild multiplier so findings are not dropped.
                confidence_factor = _confidence_factor(finding.confidence)
                final_score = round(min(raw_score * confidence_factor, 1.0), 4)
                fingerprint = _finding_fingerprint(finding)
                base_category = _categorize_risk(final_score, self.policy)
                category, category_source, category_reason = self._apply_vuln_floor(
                    finding,
                    base_category,
                )
                category, category_source, category_reason = self._apply_consistency_lock(
                    fingerprint,
                    category,
                    category_source,
                    category_reason,
                )

                scored_finding = ScoredFinding(
                    id=finding.id,
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
                    risk_score=final_score,
                    risk_category=category,
                    category_source=category_source,
                    category_reason=category_reason,
                    raw=finding.raw,
                )
                scored.append(scored_finding)

                # Debug logging — always log score components for audit
                logger.debug(
                    "SCORE %s:%d → %.4f (%s) "
                    "[base=%.2f ctx=%.2f vuln=%.2f multi=%.2f "
                    "raw_conf=%.2f conf_factor=%.2f raw_score=%.4f source=%s reason=%s]",
                    finding.file,
                    finding.line_start,
                    final_score,
                    category.value,
                    base,
                    context,
                    vuln_weight,
                    multi_tool,
                    finding.confidence,
                    confidence_factor,
                    raw_score,
                    category_source,
                    category_reason,
                )
            except Exception as e:
                logger.warning("Failed to score finding %s: %s", finding.id, e)
                continue

        self._save_cache()

        # Sort by risk score descending
        scored.sort(key=lambda f: f.risk_score, reverse=True)

        # Log summary
        critical = sum(1 for f in scored if f.risk_category == RiskCategory.CRITICAL)
        high = sum(1 for f in scored if f.risk_category == RiskCategory.HIGH)
        medium = sum(1 for f in scored if f.risk_category == RiskCategory.MEDIUM)
        low = sum(1 for f in scored if f.risk_category == RiskCategory.LOW)
        logger.info(
            "Risk scoring complete: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW",
            critical,
            high,
            medium,
            low,
        )

        return scored
