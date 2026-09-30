# Reproducible benchmark

This benchmark evaluates scanner outputs against reviewed ground truth. It is
offline and deterministic: scanner execution is separate from evaluation, so
Semgrep, ZAP, and the Security Signal Engine can be compared from saved JSON
artifacts.

## Run the example

```bash
uv run --extra dev sse-benchmark \
  --ground-truth benchmarks/ground_truth.json \
  --observed benchmarks/observed.example.json
```

The example is a format smoke test, not an accuracy claim. Replace the
placeholder cases with applications that have manually verified vulnerabilities
and verified exploit steps. Keep vulnerable and clean cases in the same
benchmark to measure both recall and false positives.

## Public benchmark data

The external corpus in `benchmarks/external/owasp-benchmark-python-v0.1/` was
retrieved from the OWASP Benchmark for Python repository on 2026-08-27. The
upstream `expectedresults-0.1.csv` contains 1,230 labeled cases: 452 real
vulnerabilities and 778 clean cases across 14 CWE categories. OWASP describes
the suite as a runnable benchmark for SAST, DAST, and IAST tools. It is a
preliminary v0.1 release under GPL-3.0; see the bundled `LICENSE` and source
README for provenance.

Import or refresh its normalized labels with:

```bash
uv run --extra dev sse-owasp-import \
  --csv benchmarks/external/owasp-benchmark-python-v0.1/expectedresults-0.1.csv \
  --output benchmarks/external/owasp-benchmark-python-v0.1/ground_truth.json
```

The current project does not yet contain scanner observations for these 1,230
cases, so no OWASP precision/recall claim is made. Start the authorized OWASP
Benchmark Python application, collect engine/Semgrep/ZAP outputs for every
case, map observations to `benchmark_id`, and pass that observation file to
`sse-benchmark`.

## Observation format

Each observation contains cases with the same `id` as the ground truth and one
or more tools. Every tool has `findings`, and may include `raw_count`,
`unique_count`, and `duration_ms`:

```json
{
  "cases": [
    {
      "id": "fixture-vulnerable-web",
      "tools": {
        "engine": {
          "raw_count": 3,
          "unique_count": 2,
          "duration_ms": 1200,
          "findings": [
            {"benchmark_id": "fixture-vulnerable-web:sqli", "risk_score": 0.91}
          ]
        }
      }
    }
  ]
}
```

Use `benchmark_id` when an adapter can map a finding to ground truth. For
unmapped tool output, provide `vuln_type`, `location`, `line_start`, and
`cwe_id`; the evaluator creates a stable fallback key from those fields.

## Metrics

The report includes true positives, false positives, false negatives,
precision, recall, F1, mean average precision, mean reciprocal rank,
Precision@1/5/10, aggregate and mean-case deduplication reduction, mean scan
duration, and p95 duration.

For a publishable evaluation, run every tool against every case, record tool
versions and configuration, repeat scans to report variance, and preserve the
raw output beside the normalized observation file. Only mark a vulnerability
in ground truth after manual review and an authorized exploit or equivalent
proof. Never benchmark against systems without permission.
