"""
Automated fine-tuning and calibration engine for the Security Signal Engine.

Provides threshold sweeping, per-rule diagnostic ranking, optimal operating
point detection (Max-F1, Precision-Priority, Recall-Priority), and automated
generation of YAML tuning profiles from empirical benchmark data.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from src.config import load_config
from src.evaluation.benchmark import evaluate_benchmark
from src.evaluation.owasp import map_engine_run_to_observed
from src.pipeline import ScanPipeline

logger = logging.getLogger(__name__)


def compute_optimal_cutoffs(
    sweep_curve: list[dict[str, Any]],
    min_precision: float = 0.80,
    min_recall: float = 0.70,
) -> dict[str, Any]:
    """
    Find optimal operating points across a threshold sweep curve.
    
    Returns:
        Dictionary of operating points: max_f1, precision_priority, recall_priority.
    """
    if not sweep_curve:
        return {}

    best_f1 = max(sweep_curve, key=lambda x: (x.get("f1", 0.0), x.get("precision", 0.0)))
    
    # Filter candidates meeting minimum precision/recall constraints
    high_prec = [x for x in sweep_curve if x.get("precision", 0.0) >= min_precision and x.get("total_predicted", 0) > 0]
    high_recall = [x for x in sweep_curve if x.get("recall", 0.0) >= min_recall]

    return {
        "max_f1": {
            "threshold": best_f1["threshold"],
            "precision": best_f1["precision"],
            "recall": best_f1["recall"],
            "f1": best_f1["f1"],
        },
        "precision_priority": (
            {
                "threshold": high_prec[0]["threshold"],
                "precision": high_prec[0]["precision"],
                "recall": high_prec[0]["recall"],
                "f1": high_prec[0]["f1"],
            }
            if high_prec
            else best_f1
        ),
        "recall_priority": (
            {
                "threshold": high_recall[-1]["threshold"],
                "precision": high_recall[-1]["precision"],
                "recall": high_recall[-1]["recall"],
                "f1": high_recall[-1]["f1"],
            }
            if high_recall
            else best_f1
        ),
    }


def generate_tuned_profile(
    rule_ranking: list[dict[str, Any]],
    operating_points: dict[str, Any],
    profile_type: str = "balanced",
    min_rule_precision: float = 0.50,
) -> dict[str, Any]:
    """
    Generate a YAML profile configuration dictionary tailored to the target operating point.
    """
    if profile_type == "precision":
        retained_rules = [
            r["rule_id"] for r in rule_ranking
            if r.get("precision", 0.0) >= 0.85 and r.get("true_positive", 0) > 0
        ]
        scoring_threshold = operating_points.get("precision_priority", {}).get("threshold", 0.70)
        return {
            "scanners_enabled": ["semgrep"],
            "semgrep": {
                "config": "p/python",
                "extra_configs": ["config/custom_python_security.yml"],
                "timeout": 120,
                "rule_allowlist": retained_rules,
            },
            "scoring": {
                "critical_threshold": round(max(0.75, scoring_threshold + 0.1), 2),
                "high_threshold": round(max(0.60, scoring_threshold), 2),
                "medium_threshold": round(max(0.45, scoring_threshold - 0.15), 2),
            },
            "llm": {"enabled": False},
            "fp_filter": {"enabled": True},
        }

    if profile_type == "recall":
        scoring_threshold = operating_points.get("recall_priority", {}).get("threshold", 0.30)
        return {
            "scanners_enabled": ["semgrep", "url-scanner"],
            "semgrep": {
                "config": "p/owasp-top-ten",
                "extra_configs": [
                    "p/security-audit",
                    "p/secrets",
                    "p/python",
                    "config/custom_python_security.yml",
                ],
                "timeout": 180,
                "rule_allowlist": [],
            },
            "scoring": {
                "critical_threshold": 0.70,
                "high_threshold": 0.50,
                "medium_threshold": 0.35,
            },
            "llm": {"enabled": True},
            "fp_filter": {"enabled": False},
        }

    # Default: balanced
    retained_rules = [
        r["rule_id"] for r in rule_ranking
        if r.get("precision", 0.0) >= min_rule_precision
    ]
    scoring_threshold = operating_points.get("max_f1", {}).get("threshold", 0.40)
    return {
        "scanners_enabled": ["semgrep"],
        "semgrep": {
            "config": "p/owasp-top-ten",
            "extra_configs": [
                "p/python",
                "p/security-audit",
                "config/custom_python_security.yml",
            ],
            "timeout": 120,
            "rule_allowlist": retained_rules,
        },
        "scoring": {
            "critical_threshold": 0.75,
            "high_threshold": 0.55,
            "medium_threshold": 0.40,
        },
        "llm": {"enabled": False},
        "fp_filter": {"enabled": True, "similarity_threshold": 0.80},
    }


def run_benchmark_tuning(
    ground_truth_path: Path,
    target_path: Path,
    output_dir: Path,
    profile_name: str = "balanced",
) -> dict[str, Any]:
    """
    Execute a full benchmark scan, evaluation, and tuning optimization pass.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(ground_truth_path, "r", encoding="utf-8-sig") as f:
        ground_truth = json.load(f)

    # 1. Load configuration for requested profile
    settings = load_config(profile=profile_name)
    pipeline = ScanPipeline(settings=settings)

    print(f"[*] Running Security Signal Engine scan (profile: {profile_name}) on {target_path}...")
    report = pipeline.run(str(target_path), generate_pdf=False)
    report_dict = report.model_dump(mode="json")

    # 2. Save raw engine report
    engine_report_path = output_dir / f"engine-{profile_name}.json"
    engine_report_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")

    # 3. Map engine scan into benchmark observed format
    print(f"[*] Mapping {len(report.findings)} findings to ground truth cases...")
    observed = map_engine_run_to_observed(report_dict, ground_truth, tool_name="engine")
    observed_path = output_dir / f"observed-{profile_name}.json"
    observed_path.write_text(json.dumps(observed, indent=2), encoding="utf-8")

    # 4. Evaluate metrics with threshold sweep & rule ranking
    print("[*] Evaluating accuracy against ground truth...")
    eval_result = evaluate_benchmark(
        ground_truth,
        observed,
        include_sweep=True,
        include_rule_ranking=True,
    )
    eval_path = output_dir / f"evaluation-{profile_name}.json"
    eval_path.write_text(json.dumps(eval_result, indent=2), encoding="utf-8")

    # 5. Compute tuning recommendations
    metric_summary = eval_result["metrics"][0] if eval_result.get("metrics") else {}
    sweep_curve = metric_summary.get("threshold_sweep", {}).get("curve", [])
    rule_ranking = metric_summary.get("rule_ranking", [])

    operating_points = compute_optimal_cutoffs(sweep_curve)

    # 6. Generate optimized profiles
    tuned_profiles = {
        "precision": generate_tuned_profile(rule_ranking, operating_points, "precision"),
        "balanced": generate_tuned_profile(rule_ranking, operating_points, "balanced"),
        "recall": generate_tuned_profile(rule_ranking, operating_points, "recall"),
    }

    tuning_summary = {
        "profile_tested": profile_name,
        "total_cases": eval_result.get("case_count", 0),
        "total_vulnerabilities": eval_result.get("ground_truth_vulnerabilities", 0),
        "true_positives": metric_summary.get("true_positive", 0),
        "false_positives": metric_summary.get("false_positive", 0),
        "false_negatives": metric_summary.get("false_negative", 0),
        "precision": metric_summary.get("precision", 0.0),
        "recall": metric_summary.get("recall", 0.0),
        "f1_score": metric_summary.get("f1", 0.0),
        "pr_auc": metric_summary.get("threshold_sweep", {}).get("pr_auc", 0.0),
        "optimal_operating_points": operating_points,
        "top_performing_rules": rule_ranking[:10] if rule_ranking else [],
        "artifacts": {
            "engine_report": str(engine_report_path),
            "observed": str(observed_path),
            "evaluation": str(eval_path),
        },
    }

    tuning_summary_path = output_dir / f"tuning_summary_{profile_name}.json"
    tuning_summary_path.write_text(json.dumps(tuning_summary, indent=2), encoding="utf-8")

    return tuning_summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated fine-tuning and evaluation for Security Signal Engine")
    parser.add_argument("--ground-truth", required=True, type=Path, help="Path to ground_truth.json")
    parser.add_argument("--target", required=True, type=Path, help="Path to benchmark testcode directory")
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/runs/tuning"), help="Output directory for tuning artifacts")
    parser.add_argument("--profile", default="balanced", choices=["default", "precision", "balanced", "recall"], help="Tuning profile preset to evaluate")
    args = parser.parse_args()

    summary = run_benchmark_tuning(
        ground_truth_path=args.ground_truth,
        target_path=args.target,
        output_dir=args.output_dir,
        profile_name=args.profile,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
