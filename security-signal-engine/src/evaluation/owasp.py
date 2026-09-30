"""Import the public OWASP Benchmark for Python expected-results CSV."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_owasp_csv(path: str | Path) -> dict[str, Any]:
    """Convert OWASP expected-results rows into this project's ground-truth schema."""
    cases = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        rows = csv.reader(line for line in handle if not line.lstrip().startswith("#"))
        for row in rows:
            if len(row) < 4 or row[0].strip().lower() in {"test name", ""}:
                continue
            test_name, category, real_vulnerability, cwe = [value.strip() for value in row[:4]]
            cases.append(
                {
                    "id": test_name,
                    "target": "OWASP Benchmark for Python v0.1",
                    "vulnerabilities": (
                        [
                            {
                                "benchmark_id": test_name,
                                "vuln_type": category.upper(),
                                "location": test_name,
                                "cwe_id": f"CWE-{cwe}",
                                "verified": True,
                            }
                        ]
                        if real_vulnerability.lower() == "true"
                        else []
                    ),
                    "metadata": {
                        "category": category,
                        "real_vulnerability": real_vulnerability.lower() == "true",
                        "cwe": f"CWE-{cwe}",
                    },
                }
            )
    if not cases:
        raise ValueError(f"No benchmark rows found in {path}")
    return {
        "version": "owasp-python-0.1",
        "source": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "license": "GPL-3.0",
        "cases": cases,
    }


def summarize_ground_truth(ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Return dataset composition useful for an evaluation report."""
    cases = ground_truth.get("cases", [])
    categories = Counter(
        case["metadata"]["category"] for case in cases if case.get("metadata")
    )
    vulnerable = sum(bool(case.get("vulnerabilities")) for case in cases)
    return {
        "cases": len(cases),
        "vulnerable_cases": vulnerable,
        "clean_cases": len(cases) - vulnerable,
        "vulnerability_rate": round(vulnerable / len(cases), 4) if cases else 0.0,
        "categories": dict(sorted(categories.items())),
    }


def map_engine_run_to_observed(
    engine_report: dict[str, Any],
    ground_truth: dict[str, Any],
    tool_name: str = "engine",
) -> dict[str, Any]:
    """Map an Engine scan output (engine.json) to benchmark observed format."""
    import re

    cases_by_id: dict[str, list[dict[str, Any]]] = {}
    for case in ground_truth.get("cases", []):
        cases_by_id[case["id"]] = []

    findings = engine_report.get("findings", [])
    for f in findings:
        file_path = f.get("file", "")
        match = re.search(r"(BenchmarkTest\d{5})", file_path)
        if not match:
            continue
        case_id = match.group(1)
        if case_id in cases_by_id:
            cases_by_id[case_id].append(
                {
                    "benchmark_id": case_id,
                    "risk_score": f.get("risk_score", 0.0),
                    "rule_id": f.get("rule_id", "unknown"),
                    "vuln_type": f.get("vuln_type", "UNKNOWN"),
                    "cwe_id": f.get("cwe_id"),
                    "confidence": f.get("confidence", 0.0),
                }
            )

    raw_count = engine_report.get("summary", {}).get("total_raw", len(findings))
    unique_count = engine_report.get("summary", {}).get("after_dedup", len(findings))
    duration_ms = float(engine_report.get("duration_ms", 0.0))

    observed_cases = []
    for case in ground_truth.get("cases", []):
        cid = case["id"]
        observed_cases.append(
            {
                "id": cid,
                "tools": {
                    tool_name: {
                        "raw_count": raw_count,
                        "unique_count": unique_count,
                        "duration_ms": duration_ms,
                        "findings": cases_by_id.get(cid, []),
                    }
                },
            }
        )

    return {
        "metadata": {
            "mapped_from": engine_report.get("scan_id", "unknown"),
            "target": "OWASP Benchmark for Python v0.1",
        },
        "cases": observed_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="OWASP Benchmark utilities for import and mapping")
    parser.add_argument("--csv", type=Path, help="Path to expectedresults-0.1.csv to import")
    parser.add_argument("--map-engine", type=Path, help="Path to engine.json to map into observed format")
    parser.add_argument("--ground-truth", type=Path, help="Path to ground_truth.json (required for mapping)")
    parser.add_argument("--output", required=True, type=Path, help="Output destination path")
    args = parser.parse_args()

    if args.csv:
        ground_truth = load_owasp_csv(args.csv)
        ground_truth["dataset_summary"] = summarize_ground_truth(ground_truth)
        args.output.write_text(json.dumps(ground_truth, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(ground_truth["dataset_summary"], indent=2))
        return 0

    if args.map_engine:
        if not args.ground_truth:
            parser.error("--ground-truth is required when using --map-engine")
        with args.ground_truth.open("r", encoding="utf-8") as h:
            gt = json.load(h)
        with args.map_engine.open("r", encoding="utf-8") as h:
            engine_rep = json.load(h)
        observed = map_engine_run_to_observed(engine_rep, gt)
        args.output.write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8")
        print(f"Mapped {len(engine_rep.get('findings', []))} findings into {args.output}")
        return 0

    parser.error("Either --csv or --map-engine must be specified")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
