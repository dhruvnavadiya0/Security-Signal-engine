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

---

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

---

## 🛠️ Security Scanners & Orchestration

The engine is designed to seamlessly run and coordinate multiple security scanners. Here is a detailed breakdown of how the scanning infrastructure works:

### 1. Scanner Orchestrator (`orchestrator.py`)
Acts as the central command hub for the entire scanning process. When a scan is initiated, the orchestrator determines the target type (local file path or live URL) and automatically dispatches the appropriate scanning tools. It manages tool lifecycles, configuration loading, unified error handling, and scan timeouts. It provides a single, unified interface for all your security tools. 

### 2. Semgrep Scanner (`semgrep.py`)
Semgrep is our primary Static Application Security Testing (SAST) engine. It performs fast, pattern-based code analysis on local repositories. The engine automatically runs Semgrep against your codebase to find vulnerabilities like hardcoded secrets, injection flaws, insecure cryptographic practices, and bad configurations. 

### 3. Built-in URL Scanner (`url_scanner.py`)
Our built-in Dynamic Application Security Testing (DAST) scanner actively probes running web applications. It performs passive checks (like missing security headers, missing secure cookie flags, and SSL certificate issues) as well as active probes targeting sensitive paths (e.g., exposed `.env` or `.git` directories) and common vulnerabilities (SQLi, XSS, SSRF, IDOR).

---

## 📋 Prerequisites

### Required

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| **Python** | >= 3.11 | `python --version` |
| **pip** | Latest | `python -m pip --version` |

### Optional (for full functionality)

| Requirement | Purpose | Install Guide |
|-------------|---------|---------------|
| **uv** / **Semgrep** | Fast dependencies / Static code analysis | `pip install uv semgrep` |
| **Ollama** | Local LLM for AI analysis | [ollama.com/download](https://ollama.com/download) |
| **Docker** | Containerized deployment | [docker.com](https://docker.com) |

---

## 🚀 Installation & Quick Start

### Option 1: Local Installation (Recommended for Development)

```bash
# 1. Navigate to the project directory
cd security-signal-engine

# 2. Install dependencies and local tools
uv sync
# Or using pip in dev mode: python -m pip install -e ".[dev]"

# 3. Check local runtimes
sse doctor

# 4. Verify installation
sse --version
```

### Option 2: Docker Installation

```bash
# 1. Navigate to the docker directory
cd security-signal-engine/docker

# 2. Build and start all services
docker compose up -d

# 3. Check logs
docker compose logs -f sse-api

# 4. The API will be available at http://localhost:8000
```

---

## 🤖 Setting Up the LLM (Optional)

The LLM provides AI-powered plain-language explanations and fix suggestions. Without it, the system falls back to high-quality deterministic templates. The project uses Ollama instead of OpenAI services. 

### 1. Install Ollama & Pull the Model

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Pull default Llama model
ollama pull llama3.1:8b

# Pull specialist model for website pentest analysis
ollama run xploiter/pentester:latest
```

### 2. Verify
Ollama should be running on port 11434 (`http://127.0.0.1:11434`). URL scans automatically route LLM enrichment to `xploiter/pentester:latest`.

---

## 🔍 Running a Scan

### CLI Scan (Most Common)

```bash
# Run a static code scan (uses Semgrep)
sse scan --path ./your-project

# Run a dynamic web scan (uses URL Scanner)
sse scan --url "https://your-website.com"

# Combined source and runtime assessment (SARIF output)
sse scan --url "https://staging.example.com" --output sarif --output-file findings.sarif

# JSON output (for programmatic use)
sse scan --path ./your-project --output json --output-file report.json

# CI/CD mode: fail if critical findings exist (Quiet mode for CI/CD)
sse scan --path ./your-project --fail-on critical --quiet

# Disable LLM (faster, uses rule-based templates)
sse scan --path ./your-project --no-llm
```

### API Scan

```bash
# 1. Start the API server
sse server

# 2. Trigger a scan via API (in another terminal)
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "/path/to/your/project"}'

# 3. Retrieve a previous scan
curl http://localhost:8000/api/v1/scan/{scan_id}
```

---

## ⚙️ Configuration

Create `sse_config.yaml` in your project root (or use `--config` flag) or set environment variables with the `SSE_` prefix (e.g. `SSE_LLM__ENABLED=false`):

```yaml
# Which scanners to run
scanners_enabled:
  - semgrep
  - url-scanner

# Semgrep settings
semgrep:
  config: "auto"          # "auto" auto-detects from project type
  timeout: 120            # Max seconds per scan

# URL Scanner settings
url_scanner:
  timeout: 15
  max_requests_per_scan: 200

# LLM settings
llm:
  provider: "ollama"
  model: "llama3.1:8b"
  enabled: true           # Set false to skip LLM enrichment
  base_url: "http://localhost:11434"

pentest_model: "xploiter/pentester:latest"

# Output defaults
output_format: "cli"
fail_on: null             # "critical", "medium", or "low"
```

---

## 🔧 Troubleshooting

### "Semgrep is not installed"
```bash
pip install semgrep
```

### "Ollama not available"
The system works without Ollama — it falls back to rule-based templates. To install: visit [ollama.com/download](https://ollama.com/download)

### Slow scans on large codebases
Increase timeout in config (`semgrep.timeout: 300`) or use specific rulesets instead of "auto" (`semgrep.config: "p/python"`).

### Import errors
Make sure you installed in editable mode: `pip install -e ".[dev]"` or ran `uv sync`.

---

## 📄 License
MIT
