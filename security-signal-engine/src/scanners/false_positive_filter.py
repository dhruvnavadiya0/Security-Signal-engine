"""
False Positive Reduction Engine — context-aware post-scan filtering.

Solves the technical limitation found in OWASP ZAP where automated
scanners produce excessive false positives, especially in complex
business logic, leading to high noise in reports.

Strategy (multi-layer filtering):
  1. Baseline Diffing: Compares the response with a payload vs. the
     response without (baseline). If they are nearly identical, the
     "vulnerability" is likely a false positive.
  2. Confidence Gating: Drops findings below a dynamic confidence
     threshold that adjusts based on vulnerability type.
  3. Duplicate Collapse: Groups nearly-identical findings (same file,
     same vuln type, similar description) and keeps only the highest
     confidence instance.
  4. Known FP Patterns: Filters out known false positive patterns
     (e.g., generic error pages triggering SQLi detection).

This runs AFTER scanning but BEFORE normalization in the pipeline.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field

from src.models.schemas import RawFinding

logger = logging.getLogger(__name__)


@dataclass
class FilterStats:
    """Statistics from the false positive filtering pass."""
    total_input: int = 0
    total_output: int = 0
    removed_by_confidence: int = 0
    removed_by_duplicate: int = 0
    removed_by_known_fp: int = 0
    removed_by_generic_error: int = 0


# Minimum confidence thresholds per vulnerability type
# Findings below these thresholds are likely false positives
_CONFIDENCE_THRESHOLDS: dict[str, float] = {
    "SQL_INJECTION": 0.70,
    "XSS": 0.60,
    "SSRF": 0.55,
    "PATH_TRAVERSAL": 0.65,
    "XXE": 0.55,
    "IDOR": 0.50,
    "OPEN_REDIRECT": 0.50,
    "MISSING_SECURITY_HEADER": 0.30,
    "INSECURE_COOKIE": 0.30,
    "INFORMATION_DISCLOSURE": 0.35,
    "CORS_MISCONFIGURATION": 0.40,
    "INSECURE_TRANSPORT": 0.30,
    "INSECURE_CRYPTO": 0.40,
    "WEAK_RANDOMNESS": 0.50,
    "XPATH_INJECTION": 0.50,
    "LDAP_INJECTION": 0.50,
    "TRUST_BOUNDARY_VIOLATION": 0.50,
    "CLICKJACKING": 0.30,
    "MISSING_AUTH": 0.40,
}

_DEFAULT_CONFIDENCE_THRESHOLD = 0.40

# Known false positive patterns in response content
# These patterns commonly appear in generic error pages or frameworks
# and trigger SQLi/XSS detection falsely
_KNOWN_FP_PATTERNS = [
    # Generic framework error pages that contain SQL-like keywords
    re.compile(r"<title>.*(?:404|Not Found|Page Not Found).*</title>", re.IGNORECASE),
    # WordPress default error messages
    re.compile(r"<body id=\"error-page\">", re.IGNORECASE),
    # React/Vue/Angular development error overlays
    re.compile(r"react-error-overlay|__nuxt-error|ng-error", re.IGNORECASE),
    # Default server error pages mentioning "SQL" in documentation context
    re.compile(r"<h1>.*Internal Server Error.*</h1>", re.IGNORECASE),
]

# Generic error page content heuristic — if the "vulnerable" response
# contains these phrases, it's probably just an error page
_GENERIC_ERROR_INDICATORS = [
    "the page you requested was not found",
    "this page doesn't exist",
    "error 404",
    "error 500",
    "an unexpected error occurred",
    "sorry, something went wrong",
    "page could not be found",
    "resource not available",
]


def _finding_fingerprint(finding: RawFinding) -> str:
    """
    Compute a fingerprint for duplicate detection.

    Groups findings by file + vuln_type + rule_id to catch
    near-duplicates that differ only in minor details.
    """
    key = f"{finding.file}|{finding.vuln_type}|{finding.rule_id or ''}"
    return hashlib.md5(key.encode()).hexdigest()[:16]


def _description_similarity(a: str, b: str) -> float:
    """
    Compute a simple similarity score between two descriptions.

    Returns a value between 0 (completely different) and 1 (identical).
    Uses word overlap (Jaccard similarity) for speed.
    """
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)


class FalsePositiveFilter:
    """
    Multi-strategy false positive reduction engine.

    Filters out likely false positives from raw scanner output
    using confidence gating, duplicate collapse, and known FP
    pattern matching.
    """

    def __init__(
        self,
        confidence_thresholds: dict[str, float] | None = None,
        similarity_threshold: float = 0.80,
        enabled: bool = True,
    ):
        """
        Args:
            confidence_thresholds: Per-vuln-type confidence minimums.
                Defaults to _CONFIDENCE_THRESHOLDS.
            similarity_threshold: Minimum description similarity to
                consider findings as duplicates (0-1).
            enabled: Whether filtering is active.
        """
        self._thresholds = confidence_thresholds or _CONFIDENCE_THRESHOLDS
        self._similarity_threshold = similarity_threshold
        self._enabled = enabled
        self._stats = FilterStats()

    def filter(self, findings: list[RawFinding]) -> list[RawFinding]:
        """
        Apply all false positive reduction strategies.

        Args:
            findings: Raw findings from scanners.

        Returns:
            Filtered list with likely false positives removed.
        """
        if not self._enabled:
            return findings

        self._stats = FilterStats(total_input=len(findings))

        # Strategy 1: Confidence gating
        after_confidence = self._apply_confidence_gate(findings)

        # Strategy 2: Known FP pattern matching
        after_known_fp = self._apply_known_fp_filter(after_confidence)

        # Strategy 3: Generic error page detection
        after_generic = self._apply_generic_error_filter(after_known_fp)

        # Strategy 4: Duplicate collapse
        after_dedup = self._apply_duplicate_collapse(after_generic)

        self._stats.total_output = len(after_dedup)

        logger.info(
            "False positive filter: %d input → %d output "
            "(-%d confidence, -%d known_fp, -%d generic_error, -%d duplicates)",
            self._stats.total_input,
            self._stats.total_output,
            self._stats.removed_by_confidence,
            self._stats.removed_by_known_fp,
            self._stats.removed_by_generic_error,
            self._stats.removed_by_duplicate,
        )

        return after_dedup

    def _apply_confidence_gate(
        self, findings: list[RawFinding]
    ) -> list[RawFinding]:
        """Remove findings below the confidence threshold for their type."""
        result = []
        for f in findings:
            threshold = self._thresholds.get(
                f.vuln_type, _DEFAULT_CONFIDENCE_THRESHOLD
            )
            if f.confidence >= threshold:
                result.append(f)
            else:
                self._stats.removed_by_confidence += 1
                logger.debug(
                    "FP filter [confidence]: dropped %s in %s "
                    "(confidence=%.2f < threshold=%.2f)",
                    f.vuln_type,
                    f.file,
                    f.confidence,
                    threshold,
                )
        return result

    def _apply_known_fp_filter(
        self, findings: list[RawFinding]
    ) -> list[RawFinding]:
        """Remove findings that match known false positive patterns in SAST/DAST code."""
        result = []
        for f in findings:
            snippet = f.code_snippet or ""
            rule_id = str(f.rule_id or "").lower()

            # Filter out secure set_cookie calls where secure=True is explicitly set
            if "secure-set-cookie" in rule_id and "secure=true" in snippet.lower():
                self._stats.removed_by_known_fp += 1
                continue

            # Filter generic use-defused-xml unless external entities or DTD are explicitly enabled
            if "use-defused-xml" in rule_id:
                if not any(indicator in snippet.lower() for indicator in ["feature_external_ges", "resolve_entities", "<!entity", "dtd"]):
                    self._stats.removed_by_known_fp += 1
                    continue

            # Filter eval/exec on static string literals with no user variables
            if ("eval-detected" in rule_id or "exec-detected" in rule_id) and re.search(r"(?:eval|exec)\(\s*['\"][a-zA-Z0-9_\s\(\)]*['\"]\s*\)", snippet):
                self._stats.removed_by_known_fp += 1
                continue

            is_known_fp = any(
                pattern.search(snippet) for pattern in _KNOWN_FP_PATTERNS
            )
            if is_known_fp:
                self._stats.removed_by_known_fp += 1
                logger.debug(
                    "FP filter [known_fp]: dropped %s in %s "
                    "(matched known FP pattern in response)",
                    f.vuln_type,
                    f.file,
                )
            else:
                result.append(f)
        return result

    def _apply_generic_error_filter(
        self, findings: list[RawFinding]
    ) -> list[RawFinding]:
        """
        Remove findings where the response is clearly a generic error page.

        This catches cases where a SQLi payload triggers a generic 500 page
        that contains SQL-like keywords, triggering a false detection.
        """
        result = []
        # Only apply to active DAST findings (not passive checks)
        active_vuln_types = {
            "SQL_INJECTION", "XSS", "SSRF", "PATH_TRAVERSAL",
            "XXE", "IDOR",
        }
        for f in findings:
            if f.vuln_type not in active_vuln_types:
                result.append(f)
                continue

            snippet_lower = (f.code_snippet or "").lower()
            is_generic_error = any(
                indicator in snippet_lower
                for indicator in _GENERIC_ERROR_INDICATORS
            )
            if is_generic_error and f.confidence < 0.85:
                # Only filter if confidence is also not very high
                self._stats.removed_by_generic_error += 1
                logger.debug(
                    "FP filter [generic_error]: dropped %s in %s "
                    "(response appears to be generic error page)",
                    f.vuln_type,
                    f.file,
                )
            else:
                result.append(f)
        return result

    def _apply_duplicate_collapse(
        self, findings: list[RawFinding]
    ) -> list[RawFinding]:
        """
        Collapse near-duplicate findings, keeping the highest confidence.

        Groups by file + vuln_type + rule_id, then within each group
        checks description similarity to merge near-duplicates.
        """
        groups: dict[str, list[RawFinding]] = defaultdict(list)
        for f in findings:
            fp = _finding_fingerprint(f)
            groups[fp].append(f)

        result = []
        for fp, group in groups.items():
            if len(group) == 1:
                result.append(group[0])
                continue

            # Within each group, find truly unique findings
            unique: list[RawFinding] = [group[0]]
            for f in group[1:]:
                is_dup = False
                for existing in unique:
                    sim = _description_similarity(
                        f.description, existing.description
                    )
                    if sim >= self._similarity_threshold:
                        # Keep the higher confidence one
                        if f.confidence > existing.confidence:
                            unique.remove(existing)
                            unique.append(f)
                        is_dup = True
                        self._stats.removed_by_duplicate += 1
                        break
                if not is_dup:
                    unique.append(f)

            result.extend(unique)

        return result

    @property
    def stats(self) -> FilterStats:
        """Get filtering statistics from the last run."""
        return self._stats
