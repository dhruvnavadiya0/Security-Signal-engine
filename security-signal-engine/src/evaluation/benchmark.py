"""Evaluate scanner reports against a versioned vulnerability ground truth.

The evaluator is intentionally independent of scanner execution. This makes
metrics reproducible from checked-in artifacts produced by the engine,
Semgrep, ZAP, or another adapter.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON object and fail with a useful error for malformed input."""
    source = Path(path)
    with source.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {source}")
    return value


def _key(item: dict[str, Any]) -> str:
    """Return the stable benchmark identity for a finding."""
    if item.get("benchmark_id"):
        return str(item["benchmark_id"])
    vuln_type = str(item.get("vuln_type", item.get("type", "UNKNOWN"))).upper()
    location = str(item.get("location", item.get("file", item.get("url", ""))))
    line = item.get("line_start", item.get("line", ""))
    cwe = str(item.get("cwe_id", item.get("cwe", ""))).upper()
    return "|".join((vuln_type, location.lower(), str(line), cwe))


def _finding_score(item: dict[str, Any]) -> float:
    value = item.get("risk_score", item.get("score", item.get("confidence", 0.0)))
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _mean(values: list[float]) -> float:
    return round(statistics.mean(values), 4) if values else 0.0


def compute_threshold_sweep(
    cases: list[dict[str, Any]],
    tool: str,
    step: float = 0.05,
) -> dict[str, Any]:
    """Compute precision, recall, and F1 across score thresholds with PR-AUC."""
    steps_count = int(round(1.0 / step)) + 1
    thresholds = [round(i * step, 4) for i in range(steps_count)]
    sweep_results: list[dict[str, Any]] = []

    for threshold in thresholds:
        tp = fp = fn = 0
        for case in cases:
            truth = case.get("vulnerabilities", [])
            expected = {_key(item) for item in truth}
            report = case.get("observed", {}).get(tool, {})
            findings = [
                f for f in report.get("findings", [])
                if _finding_score(f) >= threshold
            ]
            predicted = {_key(item) for item in findings}
            tp += len(expected & predicted)
            fp += len(predicted - expected)
            fn += len(expected - predicted)

        total_predicted = tp + fp
        total_expected = tp + fn
        precision = tp / total_predicted if total_predicted else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = tp / total_expected if total_expected else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        sweep_results.append(
            {
                "threshold": threshold,
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "total_predicted": total_predicted,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            }
        )

    # Compute PR-AUC using trapezoidal integration over unique recall points
    # Sort points by recall ascending
    curve_points: dict[float, float] = {}
    for r in sweep_results:
        rec = r["recall"]
        prec = r["precision"]
        if rec not in curve_points or prec > curve_points[rec]:
            curve_points[rec] = prec

    sorted_recalls = sorted(curve_points.keys())
    pr_auc = 0.0
    for i in range(len(sorted_recalls) - 1):
        r1, r2 = sorted_recalls[i], sorted_recalls[i + 1]
        p1, p2 = curve_points[r1], curve_points[r2]
        pr_auc += (r2 - r1) * (p1 + p2) / 2.0

    # Identify optimal operating points
    best_f1_entry = max(sweep_results, key=lambda x: (x["f1"], x["precision"]))
    high_prec_entries = [r for r in sweep_results if r["precision"] >= 0.75 and r["total_predicted"] > 0]
    high_recall_entries = [r for r in sweep_results if r["recall"] >= 0.80]

    operating_points: dict[str, Any] = {
        "max_f1": {
            "threshold": best_f1_entry["threshold"],
            "precision": best_f1_entry["precision"],
            "recall": best_f1_entry["recall"],
            "f1": best_f1_entry["f1"],
        },
        "target_precision_ge_75": (
            {
                "threshold": high_prec_entries[0]["threshold"],
                "precision": high_prec_entries[0]["precision"],
                "recall": high_prec_entries[0]["recall"],
                "f1": high_prec_entries[0]["f1"],
            }
            if high_prec_entries
            else None
        ),
        "target_recall_ge_80": (
            {
                "threshold": high_recall_entries[-1]["threshold"],
                "precision": high_recall_entries[-1]["precision"],
                "recall": high_recall_entries[-1]["recall"],
                "f1": high_recall_entries[-1]["f1"],
            }
            if high_recall_entries
            else None
        ),
    }

    return {
        "pr_auc": round(pr_auc, 4),
        "operating_points": operating_points,
        "curve": sweep_results,
    }


def compute_rule_ranking(
    cases: list[dict[str, Any]],
    tool: str,
) -> list[dict[str, Any]]:
    """Rank detection rules by measured precision and false positive contribution."""
    rule_counts: dict[str, dict[str, Any]] = {}
    total_fps_all_rules = 0

    for case in cases:
        truth = case.get("vulnerabilities", [])
        expected = {_key(item) for item in truth}
        report = case.get("observed", {}).get(tool, {})
        findings = report.get("findings", [])

        # Deduplicate findings per rule per case to evaluate case-level rule precision
        seen_case_rules: set[str] = set()
        for item in findings:
            rule_id = str(
                item.get("rule_id")
                or item.get("raw", {}).get("check_id")
                or item.get("check_id")
                or "unknown"
            )
            if rule_id in seen_case_rules:
                continue
            seen_case_rules.add(rule_id)

            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    "rule_id": rule_id,
                    "true_positive": 0,
                    "false_positive": 0,
                    "cwe_id": item.get("cwe_id") or item.get("cwe"),
                    "vuln_type": item.get("vuln_type") or item.get("type"),
                }

            if _key(item) in expected:
                rule_counts[rule_id]["true_positive"] += 1
            else:
                rule_counts[rule_id]["false_positive"] += 1
                total_fps_all_rules += 1

    ranking: list[dict[str, Any]] = []
    for r_id, stats in rule_counts.items():
        tp = stats["true_positive"]
        fp = stats["false_positive"]
        total = tp + fp
        precision = tp / total if total else 0.0
        fp_share = (fp / total_fps_all_rules) if total_fps_all_rules > 0 else 0.0
        ranking.append(
            {
                "rule_id": r_id,
                "vuln_type": stats["vuln_type"],
                "cwe_id": stats["cwe_id"],
                "true_positive": tp,
                "false_positive": fp,
                "total": total,
                "precision": round(precision, 4),
                "fp_share": round(fp_share, 4),
            }
        )

    # Sort rules: highest precision first, then highest TP, then lowest FP
    ranking.sort(
        key=lambda x: (x["precision"], x["true_positive"], -x["false_positive"]),
        reverse=True,
    )
    return ranking


def _tool_metrics(
    cases: list[dict[str, Any]],
    tool: str,
    ks: tuple[int, ...],
    include_breakdown: bool = True,
    include_sweep: bool = False,
    include_rule_ranking: bool = False,
) -> dict[str, Any]:
    true_positive = false_positive = false_negative = 0
    average_precision: list[float] = []
    precision_at_k = {str(k): [] for k in ks}
    reciprocal_ranks: list[float] = []
    reductions: list[float] = []
    total_raw = total_unique = 0
    durations: list[float] = []

    for case in cases:
        truth = case.get("vulnerabilities", [])
        expected = {_key(item) for item in truth}
        report = case.get("observed", {}).get(tool, {})
        findings = report.get("findings", [])
        predicted = {_key(item) for item in findings}
        true_positive += len(expected & predicted)
        false_positive += len(predicted - expected)
        false_negative += len(expected - predicted)

        ranked = sorted(findings, key=_finding_score, reverse=True)
        hits = 0
        precisions: list[float] = []
        first_hit = None
        for rank, item in enumerate(ranked, start=1):
            if _key(item) in expected:
                hits += 1
                if first_hit is None:
                    first_hit = rank
            precisions.append(hits / rank)
        average_precision.append((sum(precisions) / hits) if hits else 0.0)
        reciprocal_ranks.append(1 / first_hit if first_hit else 0.0)
        for k in ks:
            top = ranked[:k]
            precision_at_k[str(k)].append(
                sum(_key(item) in expected for item in top) / k
            )

        raw_count = report.get("raw_count")
        unique_count = report.get("unique_count")
        if raw_count is not None and int(raw_count) > 0 and unique_count is not None:
            raw_value = int(raw_count)
            unique_value = int(unique_count)
            reductions.append((raw_value - unique_value) / raw_value)
            total_raw += raw_value
            total_unique += unique_value
        if report.get("duration_ms") is not None:
            durations.append(float(report["duration_ms"]))

    total_expected = true_positive + false_negative
    total_predicted = true_positive + false_positive
    precision = true_positive / total_predicted if total_predicted else 0.0
    recall = true_positive / total_expected if total_expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result: dict[str, Any] = {
        "tool": tool,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "mean_average_precision": _mean(average_precision),
        "mean_reciprocal_rank": _mean(reciprocal_ranks),
        "precision_at_k": {k: _mean(values) for k, values in precision_at_k.items()},
        "deduplication_reduction": round(
            (total_raw - total_unique) / total_raw, 4
        ) if total_raw else 0.0,
        "deduplication_reduction_mean_case": _mean(reductions),
        "duration_ms_mean": _mean(durations),
        "duration_ms_p95": round(_percentile(durations, 0.95), 2),
    }

    if include_sweep:
        result["threshold_sweep"] = compute_threshold_sweep(cases, tool)

    if include_rule_ranking:
        result["rule_ranking"] = compute_rule_ranking(cases, tool)

    if include_breakdown:
        labels = sorted(
            {
                str(case.get("metadata", {}).get("category", "clean"))
                for case in cases
            }
        )
        result["per_category"] = {
            label: _tool_metrics(
                [
                    case
                    for case in cases
                    if str(case.get("metadata", {}).get("category", "clean")) == label
                ],
                tool,
                ks,
                include_breakdown=False,
                include_sweep=False,
                include_rule_ranking=False,
            )
            for label in labels
        }
    return result


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * percentile)))
    return ordered[index]


def evaluate_benchmark(
    ground_truth: dict[str, Any],
    observed: dict[str, Any],
    include_sweep: bool = False,
    include_rule_ranking: bool = False,
) -> dict[str, Any]:
    """Evaluate all tools present in the observed benchmark document."""
    truth_cases = {case["id"]: case for case in ground_truth.get("cases", [])}
    observed_cases = []
    for case in observed.get("cases", []):
        if case.get("id") not in truth_cases:
            raise ValueError(f"Observed case is missing from ground truth: {case.get('id')}")
        merged = dict(truth_cases[case["id"]])
        merged["observed"] = case.get("tools", case.get("observed", {}))
        observed_cases.append(merged)

    tools = sorted({tool for case in observed_cases for tool in case.get("observed", {})})
    metrics = [
        _tool_metrics(
            observed_cases,
            tool,
            (1, 5, 10),
            include_sweep=include_sweep,
            include_rule_ranking=include_rule_ranking,
        )
        for tool in tools
    ]
    return {
        "benchmark_version": ground_truth.get("version", 1),
        "case_count": len(observed_cases),
        "ground_truth_vulnerabilities": sum(
            len(case.get("vulnerabilities", [])) for case in observed_cases
        ),
        "clean_case_count": sum(not case.get("vulnerabilities") for case in observed_cases),
        "metrics": metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate scanner reports against benchmark ground truth")
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--observed", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sweep", action="store_true", help="Compute confidence threshold sweep and PR curve")
    parser.add_argument("--rule-ranking", action="store_true", help="Compute per-rule precision ranking")
    parser.add_argument("--tune", action="store_true", help="Compute threshold sweep, rule ranking, and tuning recommendations")
    args = parser.parse_args()
    include_sweep = args.sweep or args.tune
    include_rule_ranking = args.rule_ranking or args.tune
    result = evaluate_benchmark(
        load_json(args.ground_truth),
        load_json(args.observed),
        include_sweep=include_sweep,
        include_rule_ranking=include_rule_ranking,
    )
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
