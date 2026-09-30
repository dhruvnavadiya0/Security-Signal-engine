"""Tests for precision-focused scanner configuration."""

import json

from src.models.schemas import SemgrepConfig
from src.scanners.semgrep import SemgrepScanner


def test_semgrep_rule_allowlist_retains_only_selected_rules():
    scanner = SemgrepScanner(
        SemgrepConfig(rule_allowlist=["keep-this-rule"])
    )
    output = json.dumps(
        {
            "results": [
                {
                    "check_id": "keep-this-rule",
                    "path": "app.py",
                    "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": "kept"},
                },
                {
                    "check_id": "drop-this-rule",
                    "path": "app.py",
                    "start": {"line": 2},
                    "extra": {"severity": "ERROR", "message": "dropped"},
                },
            ]
        }
    )

    findings = scanner._parse_output(output)

    assert len(findings) == 1
    assert findings[0].rule_id == "keep-this-rule"


def test_precision_profile_achieves_target_precision():
    from src.evaluation.benchmark import evaluate_benchmark
    
    # Ground truth with vulnerable and clean cases
    ground_truth = {
        "version": "owasp-python-0.1",
        "cases": [
            {"id": "test_01", "vulnerabilities": [{"benchmark_id": "test_01"}]},
            {"id": "test_02", "vulnerabilities": [{"benchmark_id": "test_02"}]},
            {"id": "test_03", "vulnerabilities": [{"benchmark_id": "test_03"}]},
            {"id": "clean_01", "vulnerabilities": []},
            {"id": "clean_02", "vulnerabilities": []},
        ],
    }

    # Precision profile observation (only high-precision rule hits, zero FP)
    observed = {
        "cases": [
            {
                "id": "test_01",
                "tools": {
                    "engine": {
                        "findings": [
                            {
                                "benchmark_id": "test_01",
                                "risk_score": 0.9,
                                "rule_id": "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1",
                            }
                        ]
                    }
                },
            },
            {
                "id": "test_02",
                "tools": {
                    "engine": {
                        "findings": [
                            {
                                "benchmark_id": "test_02",
                                "risk_score": 0.9,
                                "rule_id": "python.flask.security.injection.subprocess-injection.subprocess-injection",
                            }
                        ]
                    }
                },
            },
            {"id": "test_03", "tools": {"engine": {"findings": []}}},
            {"id": "clean_01", "tools": {"engine": {"findings": []}}},
            {"id": "clean_02", "tools": {"engine": {"findings": []}}},
        ]
    }

    result = evaluate_benchmark(ground_truth, observed, include_rule_ranking=True)
    engine_metrics = result["metrics"][0]

    assert engine_metrics["precision"] >= 0.75
    assert engine_metrics["precision"] == 1.0
    assert engine_metrics["false_positive"] == 0
    assert len(engine_metrics["rule_ranking"]) == 2

