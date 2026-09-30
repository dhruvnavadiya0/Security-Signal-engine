# 🛡️ Security Signal Engine

**Intelligent Cybersecurity Analysis & Prioritization Platform**

Security Signal Engine sits on top of existing security tooling to dramatically reduce noise and surface only what actually matters. It aggregates scan outputs from multiple tools, normalizes them into a unified schema, deduplicates findings, and applies a dynamic risk-scoring engine. A local LLM then generates plain-language summaries, fix recommendations, and business-impact explanations.

## ✨ Core Features

- **Intelligent Normalization** — Unified finding schema across all tools
- **Smart Deduplication** — 60%+ noise reduction through rule-based clustering
- **Context-Aware Risk Scoring** — Dynamic scoring based on code context, not just CVSS
- **AI-Powered Explanations** — Local LLM generates detailed plain-English analysis
- **Graceful Fallback** — Works fully without LLM using deterministic templates
- **Beautiful Reports** — Color-coded CLI outputs and clean PDF reports
- **JSON API** — FastAPI-powered REST endpoints with auto-generated docs

## 🛠️ Security Scanners & Orchestration

The engine is designed to seamlessly run and coordinate multiple security scanners. Here is a detailed breakdown of how the scanning infrastructure works:

### 1. Scanner Orchestrator (`orchestrator.py`)
**What it does:** The orchestrator acts as the central command hub for the entire scanning process. When a scan is initiated, the orchestrator determines the target type (local file path or live URL) and automatically dispatches the appropriate scanning tools. It manages tool lifecycles, configuration loading, unified error handling, and scan timeouts.
**Why it's useful:** It provides a single, unified interface for all your security tools. Instead of memorizing the specific CLI arguments for a dozen different scanners, you just run `sse scan` and the orchestrator handles the rest. It ensures that outputs from disparate tools are properly captured and routed into the normalization pipeline, ensuring consistent results regardless of the underlying tool used.

### 2. Semgrep Scanner (`semgrep.py`)
**What it does:** Semgrep is our primary Static Application Security Testing (SAST) engine. It performs fast, pattern-based code analysis on local repositories. The engine automatically runs Semgrep against your codebase to find vulnerabilities like hardcoded secrets, injection flaws, insecure cryptographic practices, and bad configurations.
**Why it's useful:** Semgrep allows you to catch vulnerabilities at the source code level *before* they are ever deployed. Because it understands code structure rather than just using regular expressions, it produces fewer false positives. Our adapter parses Semgrep's raw JSON output and normalizes it so that it can be enriched and prioritized by the intelligence engine.

### 3. Built-in URL Scanner (`url_scanner.py`)
**What it does:** Our built-in Dynamic Application Security Testing (DAST) scanner actively probes running web applications. It performs passive checks (like missing security headers, missing secure cookie flags, and SSL certificate issues) as well as active probes targeting sensitive paths (e.g., exposed `.env` or `.git` directories) and common vulnerabilities (SQLi, XSS, SSRF, IDOR).
**Why it's useful:** While SAST (Semgrep) finds theoretical issues in code, DAST validates actual runtime vulnerabilities on your deployed application. It helps identify server misconfigurations and exposed assets that static analysis cannot see. The URL scanner is built directly into the engine, meaning you get active web probing without needing to install or configure heavy external tools like OWASP ZAP or Burp Suite.

The URL scanner also discovers common OpenAPI and Swagger documents, parses their operations, and reports API-specific review signals such as operations without declared security requirements and state-changing APIs without global security. These checks are intentionally passive; active probes should only be run against systems you own or are authorized to test.

## 🚀 Quick Start

```bash
# Install
uv sync

# Check local runtimes
sse doctor

# Run a static code scan (uses Semgrep)
sse scan --path ./your-project

# Run a dynamic web scan (uses URL Scanner)
sse scan --url "https://your-website.com"

# JSON output
sse scan --path ./your-project --output json

# SARIF output for GitHub Code Scanning
sse scan --path ./your-project --output sarif --output-file findings.sarif

# Combined source and runtime assessment
sse scan --url "https://staging.example.com" --output sarif --output-file findings.sarif

# Authorized deep web assessment with reconnaissance and active probes
sse scan --url "https://staging.example.com" --output json --output-file findings.json
```

For the deepest assessment, scan the source directory with Semgrep and the authorized staging URL separately. Source scanning covers insecure code paths, secrets, dependencies, and configuration patterns; runtime scanning covers reachable headers, cookies, exposed files, API specifications, injection, SSRF, redirects, traversal, XML, and access-control signals. Treat scanner results as evidence to verify, especially API authorization findings, which require test accounts with different privileges or tenants to prove conclusively.

The URL report also includes a bounded reconnaissance inventory: page metadata, same-origin links, forms, scripts, response headers, discovered OpenAPI/Swagger operations, and API security signals. Use only on systems you own or have explicit permission to assess, and review the generated JSON/PDF report before acting on any finding.

## 📐 Architecture

```
Target Code → Scanner Orchestration → Normalization → Deduplication
    → Risk Scoring → LLM Intelligence → Report Generation
```

| Stage | Component | Description |
|-------|-----------|-------------|
| 1 | Scanner Orchestration | Invoke scanners based on target, collect raw output |
| 2 | Normalization | Unified schema, severity mapping |
| 3 | Deduplication | Cluster duplicates, merge sources |
| 4 | Risk Scoring | Context-aware dynamic scoring |
| 5 | LLM Intelligence | AI explanations + fallback templates |
| 6 | Report Generation | CLI, JSON, PDF output |

## 🔧 Configuration

Create `sse_config.yaml` or use environment variables:

```yaml
scanners_enabled:
  - semgrep
  - url-scanner

semgrep:
  config: "auto"
  timeout: 120

url_scanner:
  timeout: 15
  max_requests_per_scan: 200

llm:
  provider: "ollama"
  model: "llama3.1"
  enabled: true

# Used automatically for URL targets
pentest_model: "xploiter/pentester:latest"

sandbox:
  enabled: false
  image: "security-signal-engine:latest"
  network: "bridge"
  memory: "2g"
  cpus: "2"
```

## Local autonomous runtime

The project uses Ollama instead of OpenAI services. Install Ollama, start it, and pull a local model:

```bash
ollama pull llama3.1:8b
```

For website pentest analysis, install and start the specialist model requested by the scan workflow:

```bash
ollama run xploiter/pentester:latest
```

The command may download the model the first time. Keep Ollama running at `http://127.0.0.1:11434`; URL scans automatically route LLM enrichment to `xploiter/pentester:latest`. Override it with `--pentest-model MODEL` or `STRIX_PENTEST_MODEL`. The model analyzes scanner evidence and proposes bounded validation; the scanner, not the model, enforces HTTP request and time budgets.

`src/core/agent_coordinator.py` provides SQLite-persisted specialist-agent state. `src/runtime/sandbox.py` provides a Docker fail-closed execution boundary for autonomous tools. Build the image before enabling sandboxed execution:

```bash
docker build -f docker/Dockerfile -t security-signal-engine:latest .
```

Run `sse doctor` before scans. Existing scans remain compatible with host execution when `sandbox.enabled` is false; autonomous tool execution should use `DockerSandbox` and must not silently fall back to the host.

## 📖 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scan` | Trigger full scan pipeline |
| GET | `/api/v1/scan/{id}` | Retrieve previous scan |
| GET | `/api/v1/health` | Health check + Ollama status |
| GET | `/api/v1/docs` | Interactive API docs |

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## 📊 Reproducible evaluation

The offline benchmark in `benchmarks/` compares saved Security Signal Engine,
Semgrep, and ZAP observations against versioned ground truth. It reports
precision, recall, F1, ranking quality, deduplication reduction, and scan
latency without requiring network access or an LLM:

```bash
uv run --extra dev sse-benchmark \
  --ground-truth benchmarks/ground_truth.json \
  --observed benchmarks/observed.example.json
```

The checked-in observations are a format smoke test. Replace them with outputs
from authorized targets and manually verified exploit evidence before using
the metrics as an accuracy claim. See `benchmarks/README.md` for the adapter
format and reporting guidance.

The visual scorecard and methodology references are in
`benchmarks/evaluation_report.md`.

An external OWASP Benchmark for Python v0.1 label corpus is included under
`benchmarks/external/`. It contains 1,230 public cases, including 452 labeled
vulnerabilities and 778 clean cases. See `benchmarks/external/owasp-benchmark-python-v0.1/README.md`
for provenance, license, and import instructions.

## 📄 License

MIT
