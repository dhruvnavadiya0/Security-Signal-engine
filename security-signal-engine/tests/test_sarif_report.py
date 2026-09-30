import json

from src.models.schemas import EnrichedFinding, RiskCategory, ScanReport, Severity
from src.reports.sarif_report import generate_sarif_report


def test_sarif_contains_code_location_and_rule_metadata():
    finding = EnrichedFinding(
        id="finding-1",
        title="SQL injection",
        file="app/routes.py",
        line_start=12,
        line_end=13,
        severity=Severity.HIGH,
        vuln_type="SQL_INJECTION",
        description="User input reaches a query.",
        confidence=0.9,
        risk_score=0.8,
        risk_category=RiskCategory.HIGH,
        cwe_id="CWE-89",
    )

    document = json.loads(generate_sarif_report(ScanReport(findings=[finding])))
    run = document["runs"][0]

    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "CWE-89"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/routes.py"


def test_sarif_rejects_unsafe_source_paths_without_dropping_finding():
    finding = EnrichedFinding(
        id="finding-2",
        file="C:\\secret.txt",
        line_start=1,
        severity=Severity.MEDIUM,
        vuln_type="INFORMATION_DISCLOSURE",
        description="Sensitive file exposed.",
        confidence=0.8,
        risk_score=0.5,
        risk_category=RiskCategory.MEDIUM,
    )

    result = json.loads(generate_sarif_report(ScanReport(findings=[finding])))['runs'][0]['results'][0]

    assert result["properties"]["sse"]["synthetic_location"] is True
    assert result["locations"][0]["logicalLocations"][0]["name"] == "C:\\secret.txt"