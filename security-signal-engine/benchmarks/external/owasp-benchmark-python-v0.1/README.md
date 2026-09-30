# OWASP Benchmark for Python v0.1

This directory contains the public expected-results data used to build the
project's external evaluation corpus.

Source: https://github.com/OWASP-Benchmark/BenchmarkPython
Expected-results source:
https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkPython/main/expectedresults-0.1.csv
License: GPL-3.0 (see `LICENSE`)
Retrieved: 2026-08-27

The source project describes this as a preliminary, runnable Python web-app
benchmark for evaluating SAST, DAST, and IAST accuracy. Its labels identify
test cases, vulnerability categories, CWE numbers, and whether each case is a
real vulnerability. The labels are not scanner observations; run the local
benchmark application and collect authorized scanner output before calculating
precision and recall.

Regenerate the normalized corpus with:

```bash
uv run --extra dev sse-owasp-import \
  --csv benchmarks/external/owasp-benchmark-python-v0.1/expectedresults-0.1.csv \
  --output benchmarks/external/owasp-benchmark-python-v0.1/ground_truth.json
```
