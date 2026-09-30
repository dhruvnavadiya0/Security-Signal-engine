"""Tests for the reproducible benchmark evaluator."""

from src.evaluation.benchmark import evaluate_benchmark


def test_benchmark_reports_detection_and_ranking_metrics():
    ground_truth = {
        "version": 1,
        "cases": [
            {
                "id": "vulnerable",
                "vulnerabilities": [
                    {"benchmark_id": "sqli"},
                    {"benchmark_id": "xss"},
                ],
            },
            {"id": "clean", "vulnerabilities": []},
        ],
    }
    observed = {
        "cases": [
            {
                "id": "vulnerable",
                "tools": {
                    "engine": {
                        "raw_count": 3,
                        "unique_count": 2,
                        "duration_ms": 100,
                        "findings": [
                            {"benchmark_id": "sqli", "risk_score": 0.9},
                            {"benchmark_id": "xss", "risk_score": 0.8},
                        ],
                    }
                },
            },
            {
                "id": "clean",
                "tools": {
                    "engine": {
                        "raw_count": 1,
                        "unique_count": 1,
                        "duration_ms": 200,
                        "findings": [{"benchmark_id": "not-in-ground-truth"}],
                    }
                },
            },
        ]
    }

    result = evaluate_benchmark(ground_truth, observed)
    metrics = result["metrics"][0]

    assert result["case_count"] == 2
    assert result["clean_case_count"] == 1
    assert metrics["true_positive"] == 2
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 0
    assert metrics["precision"] == 0.6667
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 0.8
    assert metrics["deduplication_reduction"] == 0.25
    assert metrics["deduplication_reduction_mean_case"] == 0.1667


def test_benchmark_rejects_unknown_case():
    ground_truth = {"version": 1, "cases": []}
    observed = {"cases": [{"id": "missing", "tools": {}}]}

    try:
        evaluate_benchmark(ground_truth, observed)
    except ValueError as error:
        assert "missing" in str(error)
    else:
        raise AssertionError("Unknown benchmark cases must be rejected")


def test_benchmark_threshold_sweep_and_pr_auc():
    ground_truth = {
        "version": 1,
        "cases": [
            {
                "id": "case-1",
                "vulnerabilities": [{"benchmark_id": "vuln-1"}],
            },
            {
                "id": "case-2",
                "vulnerabilities": [],
            },
        ],
    }
    observed = {
        "cases": [
            {
                "id": "case-1",
                "tools": {
                    "engine": {
                        "findings": [
                            {"benchmark_id": "vuln-1", "risk_score": 0.9},
                        ]
                    }
                },
            },
            {
                "id": "case-2",
                "tools": {
                    "engine": {
                        "findings": [
                            {"benchmark_id": "fp-1", "risk_score": 0.4},
                        ]
                    }
                },
            },
        ]
    }

    result = evaluate_benchmark(ground_truth, observed, include_sweep=True, include_rule_ranking=True)
    engine_metrics = result["metrics"][0]

    assert "threshold_sweep" in engine_metrics
    sweep = engine_metrics["threshold_sweep"]
    assert "pr_auc" in sweep
    assert "operating_points" in sweep
    assert "curve" in sweep
    assert sweep["operating_points"]["max_f1"] is not None

    # High threshold (0.5+) filters out the 0.4 FP, giving 1.0 precision
    high_thresh = next(r for r in sweep["curve"] if r["threshold"] == 0.5)
    assert high_thresh["precision"] == 1.0
    assert high_thresh["recall"] == 1.0
    assert high_thresh["f1"] == 1.0

    # Low threshold (0.0) includes 0.4 FP, giving 0.5 precision
    low_thresh = next(r for r in sweep["curve"] if r["threshold"] == 0.0)
    assert low_thresh["precision"] == 0.5
    assert low_thresh["recall"] == 1.0

    # Rule ranking checks
    assert "rule_ranking" in engine_metrics
    assert len(engine_metrics["rule_ranking"]) >= 1

