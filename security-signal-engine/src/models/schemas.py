"""
Pydantic data models for all pipeline stages of the Security Signal Engine.

These models enforce typed contracts between pipeline stages, ensuring
data integrity from raw scanner output through to final enriched reports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Standardized severity levels across all scanners."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskCategory(str, Enum):
    """Risk categories derived from the risk scoring engine."""
    CRITICAL = "CRITICAL"   # 0.75 – 1.0
    HIGH = "HIGH"           # 0.55 – 0.74
    MEDIUM = "MEDIUM"       # 0.40 – 0.54
    LOW = "LOW"             # 0.00 – 0.39


# ---------------------------------------------------------------------------
# Configuration Models
# ---------------------------------------------------------------------------

class SemgrepConfig(BaseModel):
    """Configuration for the Semgrep scanner adapter."""
    config: str = Field(default="p/owasp-top-ten", description="Primary Semgrep ruleset config")
    extra_configs: list[str] = Field(
        default_factory=lambda: ["p/security-audit", "p/secrets", "p/python"],
        description="Additional rulesets to include",
    )
    timeout: int = Field(default=120, description="Max seconds before scanner is killed")
    extra_args: list[str] = Field(default_factory=list, description="Additional CLI arguments")
    rule_allowlist: list[str] = Field(
        default_factory=list,
        description="Optional exact Semgrep rule IDs to retain for precision-focused scans",
    )


class LLMConfig(BaseModel):
    """Configuration for the LLM intelligence layer."""
    enabled: bool = Field(default=True, description="Enable LLM enrichment")
    base_url: str = Field(default="http://127.0.0.1:11434", description="Ollama API URL")
    model: str = Field(default="llama3.1", description="Ollama model name")
    temperature: float = Field(default=0.2, description="LLM temperature (low for factual output)")
    max_tokens: int = Field(default=1200, description="Max tokens per finding")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    provider: str = Field(default="ollama", description="LLM provider")
    api_key: str | None = Field(default=None, description="Optional provider API key")
    streaming: bool = Field(default=True, description="Enable provider streaming when supported")
    extra_headers: dict[str, str] = Field(default_factory=dict, description="Additional provider headers")


class URLScannerConfig(BaseModel):
    """Configuration for the URL security scanner."""
    timeout: int = Field(default=15, description="HTTP request timeout in seconds")
    max_crawl_urls: int = Field(default=20, description="Max URLs to crawl from the site")
    max_active_probe_urls: int = Field(default=10, description="Max URLs to probe for active vulns")
    max_requests_per_scan: int = Field(default=200, description="Max HTTP requests per scan (budget)")
    max_scan_seconds: int = Field(default=120, description="Max total scan time in seconds")


class RateLimiterConfig(BaseModel):
    """Configuration for the adaptive rate limiter (solves ZAP concurrency bottleneck)."""
    enabled: bool = Field(default=True, description="Enable adaptive rate limiting")
    window_size: int = Field(default=50, description="Sliding window size for health tracking")
    min_delay_ms: float = Field(default=50, description="Minimum inter-request delay in ms")
    max_delay_ms: float = Field(default=5000, description="Maximum inter-request delay in ms")


class CrawlerConfig(BaseModel):
    """Configuration for the smart crawler (solves ZAP infinite loop problem)."""
    max_depth: int = Field(default=5, description="Maximum crawl depth from start URL")
    loop_threshold: int = Field(default=3, description="Max URLs per structural pattern before loop detection")
    max_response_bytes: int = Field(default=2_000_000, description="Skip responses larger than this")


class TrafficStoreConfig(BaseModel):
    """Configuration for the traffic store (solves Burp data bloat)."""
    enabled: bool = Field(default=True, description="Enable traffic recording")
    db_path: str = Field(default=".sse/traffic.db", description="SQLite database path")
    skip_static: bool = Field(default=True, description="Skip static assets (images, fonts, CSS)")
    max_records: int = Field(default=10000, description="Maximum records before cleanup")


class OASTConfig(BaseModel):
    """Configuration for OAST blind vulnerability detection (solves Caido missing OAST)."""
    enabled: bool = Field(default=True, description="Enable OAST callback listener")
    listener_port: int = Field(default=9999, description="Port for the HTTP callback listener")
    listener_host: str = Field(default="0.0.0.0", description="Host to bind the listener")
    callback_wait_seconds: float = Field(default=2.0, description="Seconds to wait for callbacks after scan")


class FalsePositiveFilterConfig(BaseModel):
    """Configuration for false positive reduction (solves ZAP noisy reports)."""
    enabled: bool = Field(default=True, description="Enable false positive filtering")
    similarity_threshold: float = Field(default=0.80, ge=0.0, le=1.0, description="Minimum description similarity for duplicate collapse")


class PluginConfig(BaseModel):
    """Configuration for the plugin system (solves Caido immature ecosystem)."""
    enabled: bool = Field(default=True, description="Enable plugin loading")
    plugin_dir: str = Field(default="plugins", description="Directory to discover plugins from")
    enabled_plugins: list[str] = Field(default_factory=list, description="Only load these plugins (empty=all)")
    disabled_plugins: list[str] = Field(default_factory=list, description="Skip these plugins")


class SandboxConfig(BaseModel):
    """Local Docker isolation settings for autonomous tools."""
    enabled: bool = Field(default=False, description="Require Docker for autonomous tool execution")
    image: str = Field(default="security-signal-engine:latest")
    network: str = Field(default="bridge")
    memory: str = Field(default="2g")
    cpus: str = Field(default="2")
    timeout_seconds: int = Field(default=120, ge=1)


class RiskPolicyConfig(BaseModel):
    """Configuration for deterministic risk categorization policy."""
    critical_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    high_threshold: float = Field(default=0.55, ge=0.0, le=1.0)
    medium_threshold: float = Field(default=0.40, ge=0.0, le=1.0)
    min_category_by_vuln_type: dict[str, RiskCategory] = Field(
        default_factory=lambda: {
            "SQL_INJECTION": RiskCategory.HIGH,
            "RCE": RiskCategory.CRITICAL,
            "COMMAND_INJECTION": RiskCategory.HIGH,
            "SSRF": RiskCategory.HIGH,
            "INSECURE_DESERIALIZATION": RiskCategory.HIGH,
            "MISSING_AUTH": RiskCategory.HIGH,
            "SCAN_INCOMPLETE": RiskCategory.HIGH,
        },
        description="Minimum category floors by vulnerability type",
    )
    consistency_lock_enabled: bool = Field(
        default=True,
        description="Persist and reuse previous category for same warning fingerprint",
    )
    consistency_cache_path: str = Field(
        default=".sse/risk_category_cache.json",
        description="Relative or absolute path for category consistency cache",
    )
    allow_category_downgrade: bool = Field(
        default=False,
        description="Allow category to decrease when historical cache has a higher category",
    )


class ScanConfig(BaseModel):
    """Top-level configuration for a scan run."""
    scanners_enabled: list[str] = Field(default_factory=lambda: ["semgrep"])
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    url_scanner: URLScannerConfig = Field(default_factory=URLScannerConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    scoring: RiskPolicyConfig = Field(default_factory=RiskPolicyConfig)
    fail_on: Optional[str] = Field(default=None, description="Risk category to fail on (for CI/CD)")
    output_format: str = Field(default="cli", description="Output format: cli or json")
    scan_mode: str = Field(default="standard", description="Scan depth: quick, standard, or deep")
    scope_mode: str = Field(default="auto", description="Scope selection: auto, diff, or full")
    max_budget: float | None = Field(default=None, ge=0.0, description="Maximum scan budget in USD")
    max_turns: int = Field(default=20, ge=1, description="Maximum analysis turns")
    instruction: str = Field(default="", description="Additional authorized analyst instructions")
    pentest_model: str = Field(
        default="xploiter/pentester:latest",
        description="Ollama model used for authorized website pentest analysis",
    )

    # New subsystem configs (competitive feature parity)
    rate_limiter: RateLimiterConfig = Field(default_factory=RateLimiterConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    traffic_store: TrafficStoreConfig = Field(default_factory=TrafficStoreConfig)
    oast: OASTConfig = Field(default_factory=OASTConfig)
    fp_filter: FalsePositiveFilterConfig = Field(default_factory=FalsePositiveFilterConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)


# ---------------------------------------------------------------------------
# Pipeline Stage 1: Raw Finding (Scanner Output)
# ---------------------------------------------------------------------------

class RawFinding(BaseModel):
    """
    Raw finding as emitted by a security scanner.
    
    Each scanner adapter is responsible for parsing tool-specific output
    into this generic structure. The `raw` field preserves the full
    original finding for traceability.
    """
    tool_source: str = Field(..., description="Name of originating scanner (e.g. semgrep)")
    file: str = Field(..., description="Relative path to affected file")
    line_start: int = Field(..., description="Starting line number of finding")
    line_end: Optional[int] = Field(default=None, description="Ending line number")
    severity: str = Field(..., description="Tool-native severity string")
    vuln_type: str = Field(default="UNKNOWN", description="Vulnerability category")
    description: str = Field(default="", description="Human-readable description")
    rule_id: Optional[str] = Field(default=None, description="Original rule identifier from tool")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier if available")
    confidence: float = Field(default=0.5, description="Confidence score 0-1")
    code_snippet: Optional[str] = Field(default=None, description="Relevant code excerpt")
    raw: dict[str, Any] = Field(default_factory=dict, description="Full original finding")


# ---------------------------------------------------------------------------
# Pipeline Stage 2: Normalized Finding
# ---------------------------------------------------------------------------

class NormalizedFinding(BaseModel):
    """
    Finding after normalization into the unified schema.
    
    All tool-specific severity values have been mapped to the standard
    Severity enum. A UUID has been assigned. Code snippets include
    surrounding context lines.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file: str
    line_start: int
    line_end: Optional[int] = None
    severity: Severity
    vuln_type: str
    description: str
    tool_source: str
    rule_id: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    code_snippet: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pipeline Stage 3: Deduplicated Finding
# ---------------------------------------------------------------------------

class DeduplicatedFinding(BaseModel):
    """
    Finding after deduplication. Contains a `sources` list showing
    all tools that detected this issue. The finding retained is the
    one with the highest confidence score.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file: str
    line_start: int
    line_end: Optional[int] = None
    severity: Severity
    vuln_type: str
    description: str
    rule_id: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    code_snippet: Optional[str] = None
    sources: list[str] = Field(default_factory=list, description="All tools that flagged this issue")
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pipeline Stage 4: Scored Finding
# ---------------------------------------------------------------------------

class ScoredFinding(BaseModel):
    """
    Finding after risk scoring. Includes the computed risk score
    and the derived risk category.
    """
    id: str
    file: str
    line_start: int
    line_end: Optional[int] = None
    severity: Severity
    vuln_type: str
    description: str
    rule_id: Optional[str] = None
    confidence: float
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    code_snippet: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=1.0, description="Computed risk score")
    risk_category: RiskCategory = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    category_source: str = Field(
        default="score",
        description="How final category was chosen: score, vuln_floor, or consistency_cache",
    )
    category_reason: str = Field(default="", description="Audit hint for category assignment")
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pipeline Stage 5: Enriched Finding (LLM-Enhanced)
# ---------------------------------------------------------------------------

class EnrichedFinding(BaseModel):
    """
    Finding after LLM enrichment. Contains plain-language explanation,
    specific fix suggestion, and business impact assessment.
    """
    id: str
    title: str = Field(default="", description="Human-readable title")
    file: str
    line_start: int
    line_end: Optional[int] = None
    severity: Severity
    vuln_type: str
    description: str
    rule_id: Optional[str] = None
    confidence: float
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    code_snippet: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    risk_score: float
    risk_category: RiskCategory
    category_source: str = Field(default="score")
    category_reason: str = Field(default="")
    llm_explanation: str = Field(default="", description="Plain-language vulnerability explanation")
    fix_suggestion: str = Field(default="", description="Specific code-level fix recommendation")
    business_impact: str = Field(default="", description="Business risk explanation")
    attack_path: str = Field(default="", description="Evidence-backed attacker path")
    next_test: str = Field(default="", description="Next bounded authorized validation test")
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Report Models
# ---------------------------------------------------------------------------

class ScanSummary(BaseModel):
    """Summary statistics for a scan report."""
    total_raw: int = 0
    after_dedup: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanReport(BaseModel):
    """
    Complete scan report — the final output of the pipeline.
    
    Conforms to the JSON API response schema defined in PRD Section 5.7.1.
    """
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = ""
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[EnrichedFinding] = Field(default_factory=list)
    executive_summary: str = ""
    scan_duration_ms: int = 0
    report_path: Optional[str] = Field(default=None, description="Path to generated PDF report")
    scanners_used: list[str] = Field(default_factory=list, description="Scanners used for this scan")
    scanner_versions: dict[str, str] = Field(default_factory=dict, description="Scanner tool versions")
