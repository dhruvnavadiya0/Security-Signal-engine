# 🛡️ How to Run — Security Signal Engine

Complete guide to installing, configuring, and running the Security Signal Engine.

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
| **Semgrep** | Static code analysis | `pip install semgrep` |
| **Ollama** | Local LLM for AI analysis | [ollama.com/download](https://ollama.com/download) |
| **Docker** | Containerized deployment | [docker.com](https://docker.com) |

---

## 🚀 Installation

### Option 1: Local Installation (Recommended for Development)

```bash
# 1. Navigate to the project directory
cd security-signal-engine

# 2. Install in development mode with all dependencies
python -m pip install -e ".[dev]"

# 3. Verify installation
sse --version
```

### Option 2: Docker Installation

```bash
# 1. Navigate to the docker directory
cd security-signal-engine/docker

# 2. Build and start all services
docker compose up -d

# 3. The API will be available at http://localhost:8000
# 4. API docs at http://localhost:8000/api/v1/docs
```

---

## 🔍 Running a Scan

### CLI Scan (Most Common)

```bash
# Basic scan with CLI output (human-readable, color-coded)
sse scan --path /path/to/your/project

# JSON output (for programmatic use)
sse scan --path /path/to/your/project --output json

# Save JSON report to file
sse scan --path /path/to/your/project --output json --output-file report.json

# CI/CD mode: fail if critical findings exist
sse scan --path /path/to/your/project --fail-on critical

# Quiet mode for CI/CD (only errors + exit code)
sse scan --path /path/to/your/project --fail-on critical --quiet

# Disable LLM (faster, uses rule-based templates)
sse scan --path /path/to/your/project --no-llm

# Verbose logging
sse scan --path /path/to/your/project -v

# Custom config file
sse scan --path /path/to/your/project --config my_config.yaml
```

### API Scan

```bash
# 1. Start the API server
sse server

# 2. Trigger a scan via API (in another terminal)
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "/path/to/your/project"}'

# 3. Check health
curl http://localhost:8000/api/v1/health

# 4. Retrieve a previous scan
curl http://localhost:8000/api/v1/scan/{scan_id}

# 5. Interactive API docs
# Open in browser: http://localhost:8000/api/v1/docs
```

---

## ⚙️ Configuration

### Configuration File

Create `sse_config.yaml` in your project root (or use `--config` flag):

```yaml
# Which scanners to run
scanners_enabled:
  - semgrep

# Semgrep settings
semgrep:
  config: "auto"          # "auto" auto-detects from project type
  timeout: 120            # Max seconds per scan
  extra_args: []          # Additional Semgrep CLI args

# LLM settings
llm:
  model: "llama3.1:8b"
  base_url: "http://localhost:11434"
  temperature: 0.2
  max_tokens: 500
  enabled: true           # Set false to skip LLM enrichment

# Output defaults
output_format: "cli"
fail_on: null             # "critical", "medium", or "low"
```

### Environment Variables

All settings can also be set via environment variables with the `SSE_` prefix:

```bash
export SSE_LLM__ENABLED=false
export SSE_LLM__BASE_URL=http://my-ollama:11434
export SSE_SEMGREP__TIMEOUT=300
```

---

## 🤖 Setting Up the LLM (Optional)

The LLM provides AI-powered plain-language explanations and fix suggestions.
Without it, the system falls back to high-quality deterministic templates.

### Install Ollama

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows
# Download from: https://ollama.com/download
```

### Pull the Model

```bash
ollama pull llama3.1:8b
```

### Verify

```bash
# Ollama should be running on port 11434
curl http://localhost:11434/api/tags
```

### Docker (Alternative)

```bash
cd docker
docker compose up ollama -d
docker compose exec ollama ollama pull llama3.1:8b
```

---

## 🔬 Installing Semgrep

Semgrep is the primary static analysis scanner used by SSE.

```bash
# Install via pip
pip install semgrep

# Verify
semgrep --version
```

---

## 🧪 Running Tests

```bash
# Install dev dependencies
python -m pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_scoring.py -v

# Run specific test class
pytest tests/test_pipeline.py::TestPipelineEndToEnd -v
```

---

## 🐳 Docker Usage

### Full Stack (API + Ollama)

```bash
cd docker

# Start everything
docker compose up -d

# Check logs
docker compose logs -f sse-api

# Pull LLM model (first time only)
docker compose exec ollama ollama pull llama3.1:8b

# Stop
docker compose down
```

### API Only (no LLM)

```bash
cd docker

# Start just the API
docker compose up sse-api -d

# Disable LLM via environment
SSE_LLM__ENABLED=false docker compose up sse-api -d
```

---

## 🔄 CI/CD Integration

### GitHub Actions Example

```yaml
- name: Security Scan
  run: |
    pip install -e .
    sse scan --path . --fail-on critical --quiet --no-llm
```

### GitLab CI Example

```yaml
security-scan:
  script:
    - pip install -e .
    - sse scan --path . --output json --output-file security_report.json --fail-on critical --no-llm
  artifacts:
    paths:
      - security_report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no findings above threshold |
| 1 | Findings at or above `--fail-on` threshold detected |

---

## 🔧 Troubleshooting

### "Semgrep is not installed"

```bash
pip install semgrep
```

### "Ollama not available"

The system works without Ollama — it falls back to rule-based templates.
To install: visit [ollama.com/download](https://ollama.com/download)

### "No scanners available"

At least one scanner must be installed. For MVP:
```bash
pip install semgrep
```

### Slow scans on large codebases

```yaml
# Increase timeout in config
semgrep:
  timeout: 300

# Or use specific rulesets instead of "auto"
semgrep:
  config: "p/python"
```

### Import errors

Make sure you installed in editable mode:
```bash
pip install -e ".[dev]"
```

---

## 📊 Understanding the Output

### Risk Categories

| Category | Score Range | Action |
|----------|-----------|--------|
| 🔴 CRITICAL | 0.75 – 1.0 | Fix immediately. Block deploy. |
| 🟡 MEDIUM | 0.40 – 0.74 | Fix in current sprint. |
| ⚪ LOW | 0.00 – 0.39 | Track in backlog. |

### Risk Score Formula

```
Risk Score = (Base Severity × 0.4)
           + (Context Multiplier × 0.3)
           + (Vuln Type Weight × 0.2)
           + (Multi-Tool Bonus × 0.1)

Final Score = Risk Score × Confidence (0-1)
```

### CLI Report Structure

1. **Header** — Scan metadata (target, scan ID, timestamp)
2. **Summary** — Raw → deduped → severity breakdown
3. **Executive Summary** — Plain-English overview for stakeholders
4. **Critical Findings** — Detailed cards with code, explanation, fix
5. **Medium Findings** — One-line summary per finding
6. **Low Findings** — Count only
7. **Footer** — Duration and deduplication stats
