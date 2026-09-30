"""
Normalization engine.

Converts raw scanner output into the unified NormalizedFinding schema.
Applies severity mapping rules and generates consistent UUIDs.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from src.models.schemas import NormalizedFinding, RawFinding, Severity

logger = logging.getLogger(__name__)

# Severity mapping rules from PRD Table 5
_SEVERITY_MAP: dict[str, dict[str, Severity]] = {
    "semgrep": {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    },
    "url-scanner": {
        "CRITICAL": Severity.CRITICAL,
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    },
    "zap": {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFORMATIONAL": Severity.INFO,
    },
}

# Default mapping for unknown tools
_DEFAULT_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
}


def _map_severity(tool: str, raw_severity: str) -> Severity:
    """Map tool-specific severity to the unified Severity enum."""
    tool_map = _SEVERITY_MAP.get(tool.lower(), {})
    severity = tool_map.get(raw_severity.upper())
    if severity:
        return severity
    # Fall back to default mapping
    severity = _DEFAULT_SEVERITY_MAP.get(raw_severity.upper())
    if severity:
        return severity
    logger.warning(
        "Unknown severity '%s' from tool '%s', defaulting to MEDIUM",
        raw_severity,
        tool,
    )
    return Severity.MEDIUM


def _extract_code_snippet_with_context(
    file_path: str, line_start: int, context_lines: int = 2
) -> str | None:
    """
    Read source file and extract code snippet with surrounding context.
    
    Returns None if the file cannot be read.
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line_start - 1 - context_lines)
        end = min(len(lines), line_start + context_lines)
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>>" if i == line_start - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")
        return "\n".join(snippet_lines)
    except Exception as e:
        logger.debug("Could not read file for code snippet: %s", e)
        return None


class NormalizationEngine:
    """
    Converts raw scanner findings into normalized findings
    with unified severity levels, UUIDs, and enriched code snippets.
    """

    def __init__(self, target_path: str | None = None):
        self.target_path = target_path

    def normalize(self, findings: list[RawFinding]) -> list[NormalizedFinding]:
        """
        Normalize a list of raw findings into the unified schema.
        
        Args:
            findings: Raw findings from scanners.
            
        Returns:
            List of normalized findings.
        """
        normalized: list[NormalizedFinding] = []

        for raw in findings:
            try:
                severity = _map_severity(raw.tool_source, raw.severity)

                # Try to enhance code snippet with context
                code = raw.code_snippet
                if self.target_path and raw.file:
                    full_path = str(Path(self.target_path) / raw.file)
                    enhanced = _extract_code_snippet_with_context(
                        full_path, raw.line_start
                    )
                    if enhanced:
                        code = enhanced

                finding = NormalizedFinding(
                    id=str(uuid.uuid4()),
                    file=raw.file,
                    line_start=raw.line_start,
                    line_end=raw.line_end,
                    severity=severity,
                    vuln_type=raw.vuln_type,
                    description=raw.description,
                    tool_source=raw.tool_source,
                    rule_id=raw.rule_id,
                    confidence=raw.confidence,
                    cwe_id=raw.cwe_id,
                    code_snippet=code,
                    raw=raw.raw,
                )
                normalized.append(finding)
            except Exception as e:
                logger.warning("Failed to normalize finding: %s", e)
                continue

        logger.info(
            "Normalized %d findings from %d raw findings",
            len(normalized),
            len(findings),
        )
        return normalized
