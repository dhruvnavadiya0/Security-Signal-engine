"""
Deduplication engine.

Clusters findings that represent the same underlying vulnerability,
regardless of which scanner detected them or minor differences in
line number or description. Outputs a single consolidated issue for
each unique problem.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict

from src.models.schemas import DeduplicatedFinding, NormalizedFinding

logger = logging.getLogger(__name__)

# Line tolerance for considering two findings as duplicates
LINE_TOLERANCE = 5


def _dedup_key(finding: NormalizedFinding) -> str:
    """
    Generate the primary deduplication key.
    
    Primary key: file + vuln_type + bucketed line_start.
    Line numbers are bucketed by LINE_TOLERANCE to catch near-duplicates.
    """
    line_bucket = finding.line_start // LINE_TOLERANCE
    return f"{finding.file}::{finding.vuln_type}::{line_bucket}"


def _secondary_key(finding: NormalizedFinding) -> str | None:
    """
    Generate a secondary deduplication key based on CWE ID.
    Used for cross-tool matching when CWE IDs are available.
    """
    if finding.cwe_id:
        return f"{finding.file}::{finding.cwe_id}"
    return None


class DeduplicationEngine:
    """
    Deduplicates normalized findings using rule-based clustering.
    
    Strategy (from PRD Section 5.3.1):
    - Primary key: file + vuln_type + line_start (±5 line tolerance)
    - Secondary key: CWE ID match across tools
    - Retains the finding with the highest confidence score
    - Merges tool_source into sources list
    - Logs deduplication events for audit trail
    """

    def deduplicate(
        self, findings: list[NormalizedFinding]
    ) -> list[DeduplicatedFinding]:
        """
        Deduplicate a list of normalized findings.
        
        Args:
            findings: Normalized findings to deduplicate.
            
        Returns:
            Deduplicated findings with merged source information.
        """
        # Group findings by primary key
        primary_groups: dict[str, list[NormalizedFinding]] = defaultdict(list)
        for f in findings:
            primary_groups[_dedup_key(f)].append(f)

        # Secondary pass: merge groups that share CWE IDs
        secondary_map: dict[str, str] = {}  # secondary_key -> primary_key
        merged_groups: dict[str, list[NormalizedFinding]] = {}

        for pkey, group in primary_groups.items():
            target_key = pkey

            # Check if any finding in this group matches a secondary key
            for f in group:
                skey = _secondary_key(f)
                if skey and skey in secondary_map:
                    existing_pkey = secondary_map[skey]
                    if existing_pkey != pkey and existing_pkey in merged_groups:
                        # Merge into existing group
                        target_key = existing_pkey
                        break

            if target_key not in merged_groups:
                merged_groups[target_key] = []
            merged_groups[target_key].extend(group)

            # Register secondary keys
            for f in group:
                skey = _secondary_key(f)
                if skey:
                    secondary_map[skey] = target_key

        # Build deduplicated findings
        results: list[DeduplicatedFinding] = []
        total_dupes = 0

        for group_key, group in merged_groups.items():
            if len(group) > 1:
                total_dupes += len(group) - 1
                logger.debug(
                    "Dedup group '%s': %d findings merged into 1",
                    group_key,
                    len(group),
                )

            # Retain the finding with the highest confidence
            best = max(group, key=lambda f: f.confidence)

            # Collect all unique tool sources
            sources = list({f.tool_source for f in group})

            deduped = DeduplicatedFinding(
                id=str(uuid.uuid4()),
                file=best.file,
                line_start=best.line_start,
                line_end=best.line_end,
                severity=best.severity,
                vuln_type=best.vuln_type,
                description=best.description,
                rule_id=best.rule_id,
                confidence=best.confidence,
                cwe_id=best.cwe_id,
                cvss_score=best.cvss_score,
                code_snippet=best.code_snippet,
                sources=sources,
                raw=best.raw,
            )
            results.append(deduped)

        logger.info(
            "Deduplication: %d findings → %d unique (%d duplicates removed)",
            len(findings),
            len(results),
            total_dupes,
        )
        return results
