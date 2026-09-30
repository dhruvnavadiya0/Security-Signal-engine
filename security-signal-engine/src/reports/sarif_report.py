"""SARIF 2.1.0 report generation for CI code-scanning integrations."""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from src.models.schemas import EnrichedFinding, RiskCategory, ScanReport


_SARIF_LEVELS = {
    RiskCategory.CRITICAL: "error",
    RiskCategory.HIGH: "error",
    RiskCategory.MEDIUM: "warning",
    RiskCategory.LOW: "note",
}

_SECURITY_SEVERITY = {
    RiskCategory.CRITICAL: "10.0",
    RiskCategory.HIGH: "8.0",
    RiskCategory.MEDIUM: "5.0",
    RiskCategory.LOW: "2.0",
}


def _rule_id(finding: EnrichedFinding) -> str:
    """Create a stable rule key so CI systems group repeated findings."""
    if finding.rule_id:
        return finding.rule_id
    if finding.cwe_id:
        match = re.search(r"\d+", finding.cwe_id)
        if match:
            return f"CWE-{match.group()}"
    return finding.vuln_type or "SSE-UNKNOWN"


def _safe_uri(file_path: str) -> str | None:
    """Return a repository-relative path, rejecting absolute/traversal paths."""
    if not file_path or "://" in file_path:
        return None
    normalized = file_path.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", normalized):
        return None
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        return None
    return str(path)


def _message(finding: EnrichedFinding) -> str:
    return finding.llm_explanation or finding.description or finding.title


def _result(finding: EnrichedFinding) -> dict:
    result = {
        "ruleId": _rule_id(finding),
        "level": _SARIF_LEVELS[finding.risk_category],
        "message": {"text": _message(finding)},
        "kind": "fail",
        "properties": {
            "sse": {
                "finding_id": finding.id,
                "severity": finding.severity.value,
                "risk_category": finding.risk_category.value,
                "risk_score": finding.risk_score,
                "confidence": finding.confidence,
                "sources": finding.sources,
                "attack_path": finding.attack_path,
                "next_test": finding.next_test,
            }
        },
    }
    uri = _safe_uri(finding.file)
    if uri:
        region = {"startLine": max(finding.line_start, 1)}
        if finding.line_end and finding.line_end >= finding.line_start:
            region["endLine"] = finding.line_end
        result["locations"] = [{"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": region,
        }}]
    else:
        result["properties"]["sse"]["synthetic_location"] = True
        result["locations"] = [{"logicalLocations": [{"name": finding.file or "scan target"}]}]
    return result


def generate_sarif_report(report: ScanReport) -> str:
    """Serialize a scan report as a SARIF 2.1.0 document."""
    rules: dict[str, dict] = {}
    results = []
    for finding in report.findings:
        rule_id = _rule_id(finding)
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.title or finding.vuln_type or rule_id,
            "shortDescription": {"text": finding.title or finding.vuln_type or rule_id},
            "fullDescription": {"text": finding.description or _message(finding)},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[finding.risk_category],
                "cwe": finding.cwe_id,
            },
        })
        results.append(_result(finding))

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Security Signal Engine",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"sse/{report.scan_id}"},
            "invocations": [{"executionSuccessful": True}],
            "results": results,
        }],
    }
    return json.dumps(document, indent=2)


def save_sarif_report(report: ScanReport, output_path: str) -> None:
    """Write a SARIF report to disk."""
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(generate_sarif_report(report))