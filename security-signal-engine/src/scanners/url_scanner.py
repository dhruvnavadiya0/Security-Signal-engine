"""
URL-based security scanner with active DAST probing.

Performs both passive and active security analysis on a target website URL.

Passive checks:
  - Missing/misconfigured security headers
  - SSL/TLS certificate issues
  - Cookie security flags
  - Information disclosure (server banners, X-Powered-By)
  - Common vulnerable/sensitive paths
  - Mixed content issues
  - CORS misconfigurations

Active DAST checks:
  - SQL Injection probing (error-based detection)
  - Reflected XSS probing (payload reflection detection)
    - Stored XSS probing on writable forms
  - Open redirect testing
    - SSRF parameter probing
    - Path traversal probing
    - XXE probing on XML endpoints
    - IDOR pattern probing on numeric object identifiers
  - Directory listing detection
  - Dangerous HTTP methods (PUT/DELETE/TRACE)
    - Recursive link crawling for expanded attack surface

This is a built-in scanner — no external tools required.
"""

from __future__ import annotations

import logging
import re
import ssl
import socket
import time
import hashlib
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import httpx

from src.models.schemas import RawFinding
from src.scanners.base import BaseScanner, ScannerError
from src.scanners.adaptive_rate_limiter import AdaptiveRateLimiter, TargetHealthState
from src.scanners.smart_crawler import SmartCrawler
from src.scanners.traffic_store import TrafficStore
from src.scanners.oast_detector import OASTManager
from src.scanners.openapi_analyzer import discover_openapi
from src.scanners.reconnaissance import build_recon_findings

logger = logging.getLogger(__name__)


class _BudgetExceededError(TimeoutError):
    """Internal signal used to stop probing when URL scan budget is exhausted."""


# ── Security header checks ─────────────────────────────────

REQUIRED_SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "vuln_type": "MISSING_SECURITY_HEADER",
        "severity": "WARNING",
        "cwe": "CWE-319",
        "description": (
            "Missing HTTP Strict-Transport-Security (HSTS) header. "
            "Without HSTS, browsers may allow connections over insecure HTTP, "
            "making users vulnerable to man-in-the-middle attacks."
        ),
        "confidence": 0.95,
    },
    "Content-Security-Policy": {
        "vuln_type": "MISSING_SECURITY_HEADER",
        "severity": "WARNING",
        "cwe": "CWE-693",
        "description": (
            "Missing Content-Security-Policy (CSP) header. "
            "Without CSP, the site is more vulnerable to Cross-Site Scripting (XSS) "
            "and data injection attacks."
        ),
        "confidence": 0.90,
    },
    "X-Content-Type-Options": {
        "vuln_type": "MISSING_SECURITY_HEADER",
        "severity": "INFO",
        "cwe": "CWE-693",
        "description": (
            "Missing X-Content-Type-Options header. "
            "Should be set to 'nosniff' to prevent MIME-type sniffing attacks."
        ),
        "confidence": 0.95,
    },
    "X-Frame-Options": {
        "vuln_type": "CLICKJACKING",
        "severity": "WARNING",
        "cwe": "CWE-1021",
        "description": (
            "Missing X-Frame-Options header. "
            "The site may be vulnerable to clickjacking attacks where it "
            "is embedded in a malicious iframe."
        ),
        "confidence": 0.85,
    },
    "Referrer-Policy": {
        "vuln_type": "INFORMATION_DISCLOSURE",
        "severity": "INFO",
        "cwe": "CWE-200",
        "description": (
            "Missing Referrer-Policy header. "
            "Sensitive information in URLs may be leaked to third-party sites "
            "via the Referer header."
        ),
        "confidence": 0.80,
    },
    "Permissions-Policy": {
        "vuln_type": "MISSING_SECURITY_HEADER",
        "severity": "INFO",
        "cwe": "CWE-693",
        "description": (
            "Missing Permissions-Policy header. "
            "Browser features like camera, microphone, and geolocation "
            "should be explicitly restricted."
        ),
        "confidence": 0.70,
    },
}

# ── Sensitive paths to probe ────────────────────────────────

SENSITIVE_PATHS: list[dict] = [
    {
        "path": "/.env",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Exposed .env file — may contain secrets, API keys, and database credentials.",
        "cwe": "CWE-200",
    },
    {
        "path": "/.git/config",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Exposed .git directory — source code and commit history are publicly accessible.",
        "cwe": "CWE-538",
    },
    {
        "path": "/wp-admin/",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "WordPress admin panel is publicly accessible.",
        "cwe": "CWE-200",
    },
    {
        "path": "/phpinfo.php",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "PHP info page is publicly accessible — exposes server configuration details.",
        "cwe": "CWE-200",
    },
    {
        "path": "/server-status",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Apache server-status page is publicly accessible.",
        "cwe": "CWE-200",
    },
    {
        "path": "/debug",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Debug endpoint is publicly accessible — may expose sensitive application internals.",
        "cwe": "CWE-215",
    },
    {
        "path": "/api/swagger.json",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Swagger/OpenAPI spec is publicly accessible — exposes all API endpoints.",
        "cwe": "CWE-200",
    },
    {
        "path": "/actuator",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Spring Boot Actuator endpoints are publicly accessible.",
        "cwe": "CWE-200",
    },
    {
        "path": "/robots.txt",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "robots.txt may reveal hidden paths and sensitive directories.",
        "cwe": "CWE-200",
    },
    {
        "path": "/sitemap.xml",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "sitemap.xml may reveal internal URL structure.",
        "cwe": "CWE-200",
    },
    {
        "path": "/backup.sql",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "Database backup file is publicly accessible — critical data exposure.",
        "cwe": "CWE-530",
    },
    {
        "path": "/admin",
        "vuln_type": "MISSING_AUTH",
        "description": "Admin panel may be accessible without proper authentication.",
        "cwe": "CWE-306",
    },
    {
        "path": "/.DS_Store",
        "vuln_type": "INFORMATION_DISCLOSURE",
        "description": "macOS .DS_Store file is publicly accessible — may reveal directory structure.",
        "cwe": "CWE-538",
    },
    {
        "path": "/crossdomain.xml",
        "vuln_type": "CORS_MISCONFIGURATION",
        "description": "crossdomain.xml found — may allow Flash-based cross-domain requests.",
        "cwe": "CWE-942",
    },
]

# ── SQL Injection payloads & detection patterns ───────────────

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "' UNION SELECT NULL --",
    "1' AND '1'='1",
    "admin'--",
]

SQLI_BOOLEAN_PAIRS = (
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
)

SQLI_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"microsoft.*odbc.*sql", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"postgresql.*error", re.IGNORECASE),
    re.compile(r"sqlite3?\.OperationalError", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    re.compile(r"Syntax error.*in query expression", re.IGNORECASE),
    re.compile(r"SQLSTATE\[", re.IGNORECASE),
    re.compile(r"PDOException", re.IGNORECASE),
    re.compile(r"MySqlException", re.IGNORECASE),
    re.compile(r"java\.sql\.SQLException", re.IGNORECASE),
    re.compile(r"Dynamic SQL Error", re.IGNORECASE),
]

# ── XSS payloads ────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg/onload=alert(1)>',
    "'\"><script>alert(document.domain)</script>",
    '<img src=x onerror=alert(1)>',
]

# ── Open redirect params ────────────────────────────────────

REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "return_to", "returnTo",
    "redirect_url", "redirect_uri", "redir", "destination", "dest",
    "continue", "goto", "target", "link", "forward",
]

REDIRECT_TEST_URL = "https://evil.example.com"

SSRF_PARAMS = [
    "url", "uri", "target", "dest", "destination", "next", "link", "callback",
    "webhook", "image", "avatar", "redirect", "proxy", "feed",
]

SSRF_PROBES = [
    "http://127.0.0.1:80/",
    "http://localhost:80/",
    "http://169.254.169.254/latest/meta-data/",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
]

XXE_PROBE_XML = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
    "<root><item>&xxe;</item></root>"
)

IDOR_PATH_RE = re.compile(r"(?P<prefix>.*/)(?P<id>\d+)(?P<suffix>/?)$")


class URLScanner(BaseScanner):
    """
    Built-in URL security scanner with active DAST probing.

    Performs both passive checks (security headers, SSL, cookies) and
    active DAST checks (SQLi, XSS, open redirects) on a target URL.
    """

    name = "url-scanner"

    def __init__(
        self,
        timeout: int = 10,
        max_crawl_urls: int = 20,
        max_active_probe_urls: int = 10,
        max_requests_per_scan: int = 180,
        max_scan_seconds: int = 120,
        # New subsystem configs
        rate_limiter_config: dict | None = None,
        crawler_config: dict | None = None,
        traffic_store_config: dict | None = None,
        oast_config: dict | None = None,
    ):
        self.timeout = timeout
        self.max_crawl_urls = max_crawl_urls
        self.max_active_probe_urls = max_active_probe_urls
        self.max_requests_per_scan = max_requests_per_scan
        self.max_scan_seconds = max_scan_seconds
        self._request_count = 0
        self._scan_deadline = 0.0
        self._consecutive_failures = 0
        self._CONSECUTIVE_FAILURE_LIMIT = 5

        # ── Adaptive Rate Limiter (solves ZAP concurrency bottleneck) ──
        rl_cfg = rate_limiter_config or {}
        self._rate_limiter = AdaptiveRateLimiter(
            window_size=rl_cfg.get("window_size", 50),
            min_delay_ms=rl_cfg.get("min_delay_ms", 50),
            max_delay_ms=rl_cfg.get("max_delay_ms", 5000),
            enabled=rl_cfg.get("enabled", True),
        )

        # ── Smart Crawler (solves ZAP infinite loops) ──
        cr_cfg = crawler_config or {}
        self._smart_crawler = SmartCrawler(
            max_urls=max_crawl_urls,
            max_depth=cr_cfg.get("max_depth", 5),
            loop_threshold=cr_cfg.get("loop_threshold", 3),
            timeout=timeout,
            max_response_bytes=cr_cfg.get("max_response_bytes", 2_000_000),
        )

        # ── Traffic Store (solves Burp data bloat) ──
        ts_cfg = traffic_store_config or {}
        self._traffic_store = TrafficStore(
            db_path=ts_cfg.get("db_path", ".sse/traffic.db"),
            skip_static=ts_cfg.get("skip_static", True),
            max_records=ts_cfg.get("max_records", 10000),
            enabled=ts_cfg.get("enabled", True),
        )

        # ── OAST Detector (solves Caido missing OAST) ──
        oast_cfg = oast_config or {}
        self._oast_manager = OASTManager(
            listener_host=oast_cfg.get("listener_host", "0.0.0.0"),
            listener_port=oast_cfg.get("listener_port", 9999),
            enabled=oast_cfg.get("enabled", True),
        )

    def _within_budget(self) -> bool:
        """Return True while scan is still inside request/time/health limits."""
        if self._scan_deadline and time.monotonic() > self._scan_deadline:
            return False
        if self._request_count >= self.max_requests_per_scan:
            return False
        # Fail-fast: abort active probing if target is completely unresponsive
        if self._rate_limiter.health == TargetHealthState.UNRESPONSIVE:
            logger.warning(
                "Target is UNRESPONSIVE (>30%% error rate) — stopping active probes"
            )
            return False
        # Fail-fast: abort if too many consecutive connection failures
        if self._consecutive_failures >= self._CONSECUTIVE_FAILURE_LIMIT:
            logger.warning(
                "Target has %d consecutive failures — stopping active probes",
                self._consecutive_failures,
            )
            return False
        return True

    def _is_low_value_param(self, param_name: str) -> bool:
        """
        Detect parameters that are unlikely to be vulnerable.
        Optimization: Skip testing these parameters to save budget.
        """
        low_value_keywords = [
            "color", "size", "count", "limit", "offset", "page",
            "sort", "order", "lang", "currency", "theme",
            "width", "height", "opacity", "scale",
            "display", "show", "hide", "toggle",
        ]
        param_lower = param_name.lower()
        return any(kw in param_lower for kw in low_value_keywords)

    def _before_request(self) -> None:
        """Enforce global URL scan budgets and adaptive rate limiting."""
        if not self._within_budget():
            raise _BudgetExceededError("URL scan budget exceeded")
        self._request_count += 1
        # Adaptive rate limiting — waits if target is stressed
        self._rate_limiter.acquire()

    def is_available(self) -> bool:
        """URL scanner is always available (no external deps)."""
        return True

    def run(self, target: str) -> list[RawFinding]:
        """
        Scan a target URL for security issues.

        Args:
            target: Full URL to scan (e.g. https://example.com).

        Returns:
            List of RawFinding objects.
        """
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"https://{target}"
            parsed = urlparse(target)

        if parsed.scheme not in ("http", "https"):
            raise ScannerError(self.name, f"Unsupported scheme: {parsed.scheme}")

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[RawFinding] = []
        self._request_count = 0
        self._consecutive_failures = 0
        self._scan_deadline = time.monotonic() + self.max_scan_seconds

        logger.info("URL Scanner: scanning %s", base_url)

        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        )

        try:
            # ── Fetch main page ─────────────────────────────────
            try:
                response = self._fetch(target)
            except Exception as e:
                raise ScannerError(self.name, f"Cannot reach {target}: {e}")

            # ── Passive checks ──────────────────────────────────
            findings.extend(self._check_security_headers(response, target))

            if parsed.scheme == "https":
                findings.extend(self._check_ssl(parsed.netloc))

            findings.extend(self._check_cookies(response, target))
            findings.extend(self._check_info_disclosure(response, target))
            findings.extend(self._check_cors(response, target))
            findings.extend(build_recon_findings(response, target))
            findings.extend(self._check_sensitive_paths(base_url))
            findings.extend(discover_openapi(self._fetch_no_redirect, base_url))

            if parsed.scheme == "http":
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=target,
                    line_start=0,
                    severity="ERROR",
                    vuln_type="INSECURE_TRANSPORT",
                    description=(
                        "Site is served over plain HTTP. All traffic including "
                        "credentials and session tokens is transmitted in cleartext."
                    ),
                    cwe_id="CWE-319",
                    confidence=1.0,
                    raw={"url": target, "check": "insecure_transport"},
                ))

            # ── Start OAST listener for blind vuln detection ──────
            self._oast_manager.start_listener()

            # ── Active DAST probing ─────────────────────────────
            crawled_urls = self._crawl_site(base_url, target)
            all_probe_urls = [target] + crawled_urls
            probe_urls = all_probe_urls[: self.max_active_probe_urls]

            logger.info(
                "URL Scanner: probing %d URLs for active vulns concurrently",
                len(probe_urls),
            )

            probe_futures = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                for probe_url in probe_urls:
                    if not self._within_budget():
                        logger.warning(
                            "URL Scanner budget reached; stopping active probes early "
                            "(requests=%d, max=%d)",
                            self._request_count,
                            self.max_requests_per_scan,
                        )
                        break
                
                    probe_futures.extend([
                        executor.submit(self._check_sqli, probe_url),
                        executor.submit(self._check_xss, probe_url),
                        executor.submit(self._check_stored_xss, probe_url),
                        executor.submit(self._check_open_redirect, probe_url),
                        executor.submit(self._check_ssrf, probe_url),
                        executor.submit(self._check_path_traversal, probe_url),
                        executor.submit(self._check_xxe, probe_url)
                    ])

                if self._within_budget():
                    probe_futures.append(executor.submit(self._check_idor, probe_urls))
            
                # Additional active checks on base
                if self._within_budget():
                    probe_futures.append(executor.submit(self._check_directory_listing, base_url))
                if self._within_budget():
                    probe_futures.append(executor.submit(self._check_dangerous_methods, target))

                for future in concurrent.futures.as_completed(probe_futures):
                    try:
                        result = future.result()
                        if result:
                            findings.extend(result)
                    except Exception as e:
                        logger.debug("Probe task failed: %s", e)

            # ── OAST: Check for blind vulnerability callbacks ───
            confirmed_probes = self._oast_manager.check_callbacks(wait_seconds=2.0)
            for probe in confirmed_probes:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=probe.target_url,
                    line_start=0,
                    severity="CRITICAL",
                    vuln_type=f"BLIND_{probe.vuln_type}",
                    description=(
                        f"Blind {probe.vuln_type} confirmed via out-of-band callback. "
                        f"The target server made an outbound request to our OAST "
                        f"listener after injecting a payload into parameter "
                        f"'{probe.param_name}'. Callback received from "
                        f"{probe.callback_source_ip} via {probe.callback_method}."
                    ),
                    rule_id=f"oast-blind-{probe.vuln_type.lower()}",
                    cwe_id="CWE-918" if probe.vuln_type == "SSRF" else "CWE-611",
                    confidence=0.95,
                    code_snippet=(
                        f"OAST Probe: {probe.vuln_type}\n"
                        f"Target: {probe.target_url}\n"
                        f"Param: {probe.param_name}\n"
                        f"Callback from: {probe.callback_source_ip}\n"
                        f"Callback method: {probe.callback_method}"
                    ),
                    raw={
                        "oast_token": probe.token,
                        "target_url": probe.target_url,
                        "param_name": probe.param_name,
                        "callback_ip": probe.callback_source_ip,
                        "callback_method": probe.callback_method,
                    },
                ))

            self._oast_manager.stop_listener()

            # ── Log subsystem stats ─────────────────────────────
            rl_stats = self._rate_limiter.get_stats()
            oast_stats = self._oast_manager.get_stats()
            traffic_stats = self._traffic_store.get_stats()
            logger.info(
                "URL Scanner subsystem stats: "
                "rate_limiter=[health=%s, throttled=%d, avg_rt=%.0fms] "
                "oast=[probes=%d, callbacks=%d, confirmed=%d] "
                "traffic=[recorded=%d, filtered=%d, deduped=%d]",
                rl_stats.target_health.value,
                rl_stats.total_throttled,
                rl_stats.avg_response_time_ms,
                oast_stats.total_probes_generated,
                oast_stats.total_callbacks_received,
                oast_stats.confirmed_vulns,
                traffic_stats.total_recorded,
                traffic_stats.total_filtered,
                traffic_stats.total_deduplicated,
            )

        finally:
            self._client.close()

        logger.info("URL Scanner: found %d issues for %s", len(findings), base_url)
        return findings

    # ── HTTP helpers ─────────────────────────────────────────

    def _fetch(self, url: str, **kwargs) -> httpx.Response:
        """Fetch a URL, record traffic, and update rate limiter health."""
        max_retries = 2
        for attempt in range(max_retries + 1):
            self._before_request()
            start_time = time.monotonic()
            try:
                resp = self._client.get(url, headers={
                    "User-Agent": "SecuritySignalEngine/1.0 (Security Scanner)"
                }, **kwargs)

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record in adaptive rate limiter
                self._rate_limiter.record_response(
                    status_code=resp.status_code,
                    response_time_ms=elapsed_ms,
                )

                # Record in traffic store (auto-filters static assets)
                self._traffic_store.record(
                    method="GET",
                    url=url,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    response_size=len(resp.content),
                    response_time_ms=elapsed_ms,
                )

                # Success — reset consecutive failure counter
                self._consecutive_failures = 0
                return resp
            except Exception as e:
                elapsed_ms = (time.monotonic() - start_time) * 1000
                self._rate_limiter.record_response(
                    status_code=0,
                    response_time_ms=elapsed_ms,
                    is_connection_error=True,
                )
                if attempt < max_retries:
                    time.sleep(1) # simple backoff
                    continue
                self._consecutive_failures += 1
                raise

    def _post(self, url: str, data: dict | None = None) -> httpx.Response | None:
        """POST to a URL, returning None on failure."""
        try:
            self._before_request()
            return self._client.post(url, data=data, headers={
                "User-Agent": "SecuritySignalEngine/1.0 (Security Scanner)"
            })
        except Exception:
            return None

    def _fetch_no_redirect(self, url: str) -> httpx.Response | None:
        """Fetch without following redirects, returning None on failure."""
        try:
            self._before_request()
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,
            ) as client:
                return client.get(url, headers={
                    "User-Agent": "SecuritySignalEngine/1.0 (Security Scanner)"
                })
        except Exception:
            return None

    # ── Passive checks ──────────────────────────────────────

    def _check_security_headers(
        self, response: httpx.Response, url: str
    ) -> list[RawFinding]:
        """Check for missing or misconfigured security headers."""
        findings: list[RawFinding] = []

        for header_name, meta in REQUIRED_SECURITY_HEADERS.items():
            value = response.headers.get(header_name)
            if not value:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity=meta["severity"],
                    vuln_type=meta["vuln_type"],
                    description=meta["description"],
                    rule_id=f"header-missing-{header_name.lower()}",
                    cwe_id=meta["cwe"],
                    confidence=meta["confidence"],
                    code_snippet=f"Response headers: {header_name} = (not set)",
                    raw={"url": url, "header": header_name, "check": "missing_header"},
                ))

        # Check CSP quality if present
        csp = response.headers.get("Content-Security-Policy", "")
        if csp and "unsafe-inline" in csp:
            findings.append(RawFinding(
                tool_source=self.name,
                file=url,
                line_start=0,
                severity="WARNING",
                vuln_type="XSS",
                description=(
                    "Content-Security-Policy contains 'unsafe-inline', which "
                    "significantly weakens XSS protection. Inline scripts and "
                    "styles should use nonces or hashes instead."
                ),
                rule_id="header-csp-unsafe-inline",
                cwe_id="CWE-79",
                confidence=0.80,
                code_snippet=f"CSP: {csp[:200]}",
                raw={"url": url, "header": "Content-Security-Policy", "value": csp},
            ))

        if csp and "unsafe-eval" in csp:
            findings.append(RawFinding(
                tool_source=self.name,
                file=url,
                line_start=0,
                severity="WARNING",
                vuln_type="XSS",
                description=(
                    "Content-Security-Policy contains 'unsafe-eval', which allows "
                    "eval() and similar functions, increasing XSS attack surface."
                ),
                rule_id="header-csp-unsafe-eval",
                cwe_id="CWE-79",
                confidence=0.75,
                code_snippet=f"CSP: {csp[:200]}",
                raw={"url": url, "header": "Content-Security-Policy", "value": csp},
            ))

        return findings

    def _check_ssl(self, hostname: str) -> list[RawFinding]:
        """Check SSL/TLS certificate and configuration."""
        findings: list[RawFinding] = []

        host = hostname.split(":")[0]
        port = int(hostname.split(":")[1]) if ":" in hostname else 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    if protocol and protocol in ("TLSv1", "TLSv1.1"):
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=f"https://{hostname}",
                            line_start=0,
                            severity="ERROR",
                            vuln_type="INSECURE_CRYPTO",
                            description=(
                                f"Site uses deprecated TLS version: {protocol}. "
                                "TLS 1.0 and 1.1 have known vulnerabilities. "
                                "Upgrade to TLS 1.2 or 1.3."
                            ),
                            cwe_id="CWE-326",
                            confidence=0.95,
                            code_snippet=f"TLS Version: {protocol}",
                            raw={"hostname": hostname, "tls_version": protocol},
                        ))
        except ssl.SSLCertVerificationError as e:
            findings.append(RawFinding(
                tool_source=self.name,
                file=f"https://{hostname}",
                line_start=0,
                severity="ERROR",
                vuln_type="INSECURE_CRYPTO",
                description=(
                    f"SSL certificate verification failed: {e}. "
                    "Users may see browser warnings, and connections "
                    "may be vulnerable to MITM attacks."
                ),
                cwe_id="CWE-295",
                confidence=0.95,
                code_snippet=f"SSL Error: {str(e)[:200]}",
                raw={"hostname": hostname, "error": str(e)},
            ))
        except Exception as e:
            logger.debug("SSL check failed for %s: %s", hostname, e)

        return findings

    def _check_cookies(
        self, response: httpx.Response, url: str
    ) -> list[RawFinding]:
        """Check cookie security flags."""
        findings: list[RawFinding] = []
        parsed = urlparse(url)

        for cookie_header in response.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()

            is_session = any(
                kw in cookie_name.lower()
                for kw in ("session", "sid", "token", "auth", "jwt", "csrf")
            )

            if parsed.scheme == "https" and "secure" not in cookie_lower:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="WARNING" if is_session else "INFO",
                    vuln_type="INSECURE_COOKIE",
                    description=(
                        f"Cookie '{cookie_name}' is missing the Secure flag. "
                        "It may be transmitted over insecure HTTP connections."
                    ),
                    rule_id="cookie-missing-secure",
                    cwe_id="CWE-614",
                    confidence=0.90 if is_session else 0.60,
                    code_snippet=f"Set-Cookie: {cookie_header[:200]}",
                    raw={"url": url, "cookie": cookie_name},
                ))

            if is_session and "httponly" not in cookie_lower:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="WARNING",
                    vuln_type="INSECURE_COOKIE",
                    description=(
                        f"Session cookie '{cookie_name}' is missing the HttpOnly flag. "
                        "It can be accessed by JavaScript, making it vulnerable to XSS-based theft."
                    ),
                    rule_id="cookie-missing-httponly",
                    cwe_id="CWE-1004",
                    confidence=0.90,
                    code_snippet=f"Set-Cookie: {cookie_header[:200]}",
                    raw={"url": url, "cookie": cookie_name},
                ))

            if is_session and "samesite" not in cookie_lower:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="INFO",
                    vuln_type="INSECURE_COOKIE",
                    description=(
                        f"Session cookie '{cookie_name}' is missing the SameSite attribute. "
                        "This may make the application vulnerable to CSRF attacks."
                    ),
                    rule_id="cookie-missing-samesite",
                    cwe_id="CWE-352",
                    confidence=0.75,
                    code_snippet=f"Set-Cookie: {cookie_header[:200]}",
                    raw={"url": url, "cookie": cookie_name},
                ))

        return findings

    def _check_info_disclosure(
        self, response: httpx.Response, url: str
    ) -> list[RawFinding]:
        """Check for information disclosure in response headers."""
        findings: list[RawFinding] = []

        # Server banner
        server = response.headers.get("Server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(RawFinding(
                tool_source=self.name,
                file=url,
                line_start=0,
                severity="INFO",
                vuln_type="INFORMATION_DISCLOSURE",
                description=(
                    f"Server header discloses version information: '{server}'. "
                    "Attackers can use this to find known vulnerabilities for this version."
                ),
                rule_id="info-server-version",
                cwe_id="CWE-200",
                confidence=0.85,
                code_snippet=f"Server: {server}",
                raw={"url": url, "header": "Server", "value": server},
            ))

        # X-Powered-By
        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(RawFinding(
                tool_source=self.name,
                file=url,
                line_start=0,
                severity="INFO",
                vuln_type="INFORMATION_DISCLOSURE",
                description=(
                    f"X-Powered-By header discloses technology stack: '{powered_by}'. "
                    "Remove this header to reduce the attack surface."
                ),
                rule_id="info-x-powered-by",
                cwe_id="CWE-200",
                confidence=0.90,
                code_snippet=f"X-Powered-By: {powered_by}",
                raw={"url": url, "header": "X-Powered-By", "value": powered_by},
            ))

        # X-AspNet-Version
        aspnet = response.headers.get("X-AspNet-Version", "")
        if aspnet:
            findings.append(RawFinding(
                tool_source=self.name,
                file=url,
                line_start=0,
                severity="INFO",
                vuln_type="INFORMATION_DISCLOSURE",
                description=(
                    f"X-AspNet-Version header discloses ASP.NET version: '{aspnet}'."
                ),
                rule_id="info-aspnet-version",
                cwe_id="CWE-200",
                confidence=0.90,
                code_snippet=f"X-AspNet-Version: {aspnet}",
                raw={"url": url, "header": "X-AspNet-Version", "value": aspnet},
            ))

        return findings

    def _check_cors(
        self, response: httpx.Response, url: str
    ) -> list[RawFinding]:
        """Check for CORS misconfigurations."""
        findings: list[RawFinding] = []

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="ERROR",
                    vuln_type="CORS_MISCONFIGURATION",
                    description=(
                        "CORS allows all origins (*) with credentials enabled. "
                        "This is a critical misconfiguration that allows any website "
                        "to make authenticated requests on behalf of users."
                    ),
                    rule_id="cors-wildcard-credentials",
                    cwe_id="CWE-942",
                    confidence=0.95,
                    code_snippet=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    raw={"url": url, "acao": acao, "acac": acac},
                ))
            else:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="INFO",
                    vuln_type="CORS_MISCONFIGURATION",
                    description=(
                        "CORS allows all origins (*). While credentials are not "
                        "included, this may expose public API data to any website."
                    ),
                    rule_id="cors-wildcard",
                    cwe_id="CWE-942",
                    confidence=0.60,
                    code_snippet=f"Access-Control-Allow-Origin: {acao}",
                    raw={"url": url, "acao": acao},
                ))

        return findings

    def _check_sensitive_paths(self, base_url: str) -> list[RawFinding]:
        """Probe for commonly exposed sensitive files and directories."""
        findings: list[RawFinding] = []

        def _check_single_path(entry):
            if not self._within_budget():
                return None
            path = entry["path"]
            full_url = urljoin(base_url, path)

            try:
                resp = self._fetch_no_redirect(full_url)
                if resp and resp.status_code == 200 and len(resp.content) > 0:
                    content_lower = resp.text[:500].lower()
                    if "not found" in content_lower or "404" in content_lower:
                        return None

                    severity = "ERROR" if entry["vuln_type"] != "INFORMATION_DISCLOSURE" else "WARNING"
                    if path in ("/.env", "/.git/config", "/backup.sql"):
                        severity = "ERROR"

                    return RawFinding(
                        tool_source=self.name,
                        file=full_url,
                        line_start=0,
                        severity=severity,
                        vuln_type=entry["vuln_type"],
                        description=entry["description"],
                        rule_id=f"sensitive-path-{path.strip('/').replace('/', '-')}",
                        cwe_id=entry["cwe"],
                        confidence=0.85,
                        code_snippet=(
                            f"GET {path} → HTTP {resp.status_code}\n"
                            f"Content-Length: {len(resp.content)} bytes\n"
                            f"Preview: {resp.text[:150]}"
                        ),
                        raw={
                            "url": full_url,
                            "status": resp.status_code,
                            "path": path,
                        },
                    )
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_check_single_path, entry) for entry in SENSITIVE_PATHS]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
        return findings

    # ── Active DAST checks ──────────────────────────────────

    def _extract_links(self, body: str, base_url: str, from_url: str) -> list[str]:
        """Extract same-origin links from HTML content."""
        parsed_base = urlparse(base_url)
        discovered: set[str] = set()

        href_pattern = re.compile(
            r'(?:href|action)\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        for match in href_pattern.finditer(body[:100_000]):
            href = match.group(1).strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            full_url = urljoin(from_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc != parsed_base.netloc:
                continue

            clean = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                "",
            ))
            discovered.add(clean)

        return list(discovered)

    def _crawl_site(self, base_url: str, start_url: str) -> list[str]:
        """
        Crawl same-origin links using the SmartCrawler with loop detection.

        Replaces the old naive BFS crawler. The SmartCrawler normalizes
        URL structures and detects infinite loops via structural hashing,
        solving ZAP's infinite crawl loop limitation.
        """
        urls = self._smart_crawler.crawl(
            base_url=base_url,
            start_url=start_url,
            budget_check=self._within_budget,
            request_hook=self._before_request,
        )

        # Log loop detection results
        loop_report = self._smart_crawler.get_loop_report()
        loops = {k: v for k, v in loop_report.items() if v.get("is_loop")}
        if loops:
            logger.info(
                "Smart crawler detected %d URL loop pattern(s) — "
                "prevented infinite crawling",
                len(loops),
            )

        return urls[:self.max_crawl_urls]

    def _check_sqli(self, url: str) -> list[RawFinding]:
        """
        Test URL parameters for SQL Injection via error-based detection.
        Injects SQLi payloads into each query parameter and checks
        response for database error messages.
        """
        findings: list[RawFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # Try probing common param names on the URL even without existing params
            common_params = ["id", "user", "search", "q", "page", "category"]
            for param_name in common_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}="
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if params:
                    findings.extend(self._sqli_probe_params(test_url, parsed, params))
        else:
            findings.extend(self._sqli_probe_params(url, parsed, params))

        # Also test POST form if it's a form-like page
        findings.extend(self._sqli_probe_forms(url))

        return findings

    def _sqli_probe_params(
        self, url: str, parsed, params: dict
    ) -> list[RawFinding]:
        """Inject SQLi payloads into URL params and detect errors."""
        findings: list[RawFinding] = []

        # Optimization: Skip low-value parameters
        candidate_params = [
            p for p in list(params.keys())[:8]
            if not self._is_low_value_param(p)
        ]

        for param_name in candidate_params:
            if not self._within_budget():
                return findings

            # Compare safe true/false predicates against a baseline. A stable
            # response difference is stronger evidence than reflection alone.
            try:
                baseline = self._fetch(url)
                baseline_signature = self._response_signature(baseline)
                for true_payload, false_payload in SQLI_BOOLEAN_PAIRS:
                    if not self._within_budget():
                        return findings
                    true_url = self._replace_query_param(parsed, params, param_name, true_payload)
                    false_url = self._replace_query_param(parsed, params, param_name, false_payload)
                    true_response = self._fetch(true_url)
                    false_response = self._fetch(false_url)
                    true_signature = self._response_signature(true_response)
                    false_signature = self._response_signature(false_response)
                    if (true_signature != false_signature and
                            true_signature != baseline_signature and
                            false_signature != baseline_signature):
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="ERROR",
                            vuln_type="SQL_INJECTION",
                            description=(
                                f"Potential SQL injection via parameter '{param_name}': "
                                "safe boolean predicates produced distinct response signatures. "
                                "Confirm manually with an authorized test fixture before remediation."
                            ),
                            rule_id="sqli-boolean-differential",
                            cwe_id="CWE-89",
                            confidence=0.75,
                            code_snippet=(
                                f"Baseline: GET {url}\n"
                                f"True predicate: GET {true_url}\n"
                                f"False predicate: GET {false_url}\n"
                                f"Signatures: {baseline_signature}, {true_signature}, {false_signature}"
                            ),
                            raw={"url": url, "param": param_name, "method": "GET", "evidence": "boolean_differential"},
                        ))
                        return findings
            except _BudgetExceededError:
                return findings
            except Exception:
                pass

            for payload in SQLI_PAYLOADS[:5]:  # Cap at 5 payloads per param
                if not self._within_budget():
                    return findings
                test_params = dict(params)
                test_params[param_name] = [payload]
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, "",
                ))

                try:
                    resp = self._fetch(test_url)
                    body = resp.text[:5000]

                    for pattern in SQLI_ERROR_PATTERNS:
                        if pattern.search(body):
                            findings.append(RawFinding(
                                tool_source=self.name,
                                file=url,
                                line_start=0,
                                severity="CRITICAL",
                                vuln_type="SQL_INJECTION",
                                description=(
                                    f"SQL Injection detected via parameter '{param_name}'. "
                                    f"The payload '{payload}' triggered a database error "
                                    f"in the response, confirming the parameter is vulnerable "
                                    f"to SQL injection attacks. "
                                    f"Error pattern matched: {pattern.pattern}"
                                ),
                                rule_id="sqli-error-based",
                                cwe_id="CWE-89",
                                confidence=0.90,
                                code_snippet=(
                                    f"Request: GET {test_url}\n"
                                    f"Payload: {param_name}={payload}\n"
                                    f"Response excerpt: {body[:300]}"
                                ),
                                raw={
                                    "url": url,
                                    "param": param_name,
                                    "payload": payload,
                                    "pattern": pattern.pattern,
                                },
                            ))
                            # One finding per param is enough
                            return findings
                except _BudgetExceededError:
                    return findings
                except Exception:
                    continue

        return findings

    @staticmethod
    def _response_signature(response: httpx.Response) -> tuple[int, int, str]:
        """Build a low-cost comparison signature without storing response data."""
        body = response.text[:100_000]
        return response.status_code, len(body), hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]

    @staticmethod
    def _replace_query_param(parsed, params: dict, name: str, value: str) -> str:
        """Create a test URL while preserving unrelated query parameters."""
        test_params = dict(params)
        test_params[name] = [value]
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params,
            urlencode(test_params, doseq=True), "",
        ))

    def _sqli_probe_forms(self, url: str) -> list[RawFinding]:
        """Probe HTML forms on the page for SQLi via POST."""
        findings: list[RawFinding] = []

        try:
            resp = self._fetch(url)
            body = resp.text[:50_000]

            # Extract form fields
            input_pattern = re.compile(
                r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
                re.IGNORECASE,
            )
            form_action_pattern = re.compile(
                r'<form[^>]*action\s*=\s*["\']([^"\']*)["\'][^>]*>',
                re.IGNORECASE,
            )

            field_names = input_pattern.findall(body)
            form_actions = form_action_pattern.findall(body)

            if not field_names:
                return findings

            action_url = urljoin(url, form_actions[0]) if form_actions else url

            for payload in SQLI_PAYLOADS[:3]:
                if not self._within_budget():
                    return findings
                form_data = {name: payload for name in field_names[:5]}
                post_resp = self._post(action_url, data=form_data)
                if post_resp is None:
                    continue

                post_body = post_resp.text[:5000]
                for pattern in SQLI_ERROR_PATTERNS:
                    if pattern.search(post_body):
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="CRITICAL",
                            vuln_type="SQL_INJECTION",
                            description=(
                                f"SQL Injection detected via POST form. "
                                f"Fields tested: {', '.join(field_names[:5])}. "
                                f"Payload '{payload}' triggered a database error. "
                                f"Error pattern: {pattern.pattern}"
                            ),
                            rule_id="sqli-form-post",
                            cwe_id="CWE-89",
                            confidence=0.90,
                            code_snippet=(
                                f"POST {action_url}\n"
                                f"Form fields: {field_names[:5]}\n"
                                f"Payload: {payload}\n"
                                f"Response: {post_body[:300]}"
                            ),
                            raw={
                                "url": url,
                                "action": action_url,
                                "fields": field_names[:5],
                                "payload": payload,
                            },
                        ))
                        return findings

        except _BudgetExceededError:
            return findings
        except Exception as e:
            logger.debug("Form SQLi probe failed: %s", e)

        return findings

    def _check_xss(self, url: str) -> list[RawFinding]:
        """
        Test URL parameters for reflected XSS.
        Injects XSS payloads and checks if they appear unescaped in response.
        """
        findings: list[RawFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # Try common params
            common_params = ["q", "search", "name", "input", "query", "message"]
            for param_name in common_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}="
                test_parsed = urlparse(test_url)
                test_params = parse_qs(test_parsed.query, keep_blank_values=True)
                if test_params:
                    findings.extend(
                        self._xss_probe_params(test_url, test_parsed, test_params)
                    )
                    if findings:
                        return findings
            return findings

        return self._xss_probe_params(url, parsed, params)

    def _xss_probe_params(
        self, url: str, parsed, params: dict
    ) -> list[RawFinding]:
        """Inject XSS payloads into URL params and detect reflection."""
        findings: list[RawFinding] = []

        # Optimization: Skip low-value parameters
        candidate_params = [
            p for p in list(params.keys())[:8]
            if not self._is_low_value_param(p)
        ]

        for param_name in candidate_params:
            if not self._within_budget():
                return findings
            for payload in XSS_PAYLOADS[:3]:  # Reduced from 4 to 3
                if not self._within_budget():
                    return findings
                test_params = dict(params)
                test_params[param_name] = [payload]
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, "",
                ))

                try:
                    resp = self._fetch(test_url)
                    body = resp.text

                    # Check if payload is reflected unescaped
                    if payload in body:
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="ERROR",
                            vuln_type="XSS",
                            description=(
                                f"Reflected XSS detected via parameter '{param_name}'. "
                                f"The payload '{payload}' was reflected unescaped "
                                f"in the HTTP response body. An attacker can inject "
                                f"malicious JavaScript that executes in victims' browsers."
                            ),
                            rule_id="xss-reflected",
                            cwe_id="CWE-79",
                            confidence=0.85,
                            code_snippet=(
                                f"Request: GET {test_url}\n"
                                f"Payload: {param_name}={payload}\n"
                                f"Reflection found in response body"
                            ),
                            raw={
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "reflected": True,
                            },
                        ))
                        return findings
                except _BudgetExceededError:
                    return findings
                except Exception:
                    continue

        return findings

    def _check_open_redirect(self, url: str) -> list[RawFinding]:
        """
        Test for open redirect vulnerabilities by injecting external
        URLs into redirect-related parameters.
        """
        findings: list[RawFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Test both existing params and common redirect param names
        test_params_list = list(params.keys()) if params else []
        # Also try adding common redirect params
        for p in REDIRECT_PARAMS:
            if p not in test_params_list:
                test_params_list.append(p)

        for param_name in test_params_list[:8]:
            if not self._within_budget():
                return findings
            test_params = dict(params) if params else {}
            test_params[param_name] = [REDIRECT_TEST_URL]
            query_string = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query_string, "",
            ))

            resp = self._fetch_no_redirect(test_url)
            if resp is None:
                continue

            # Check for redirect to evil domain
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.example.com" in location:
                    findings.append(RawFinding(
                        tool_source=self.name,
                        file=url,
                        line_start=0,
                        severity="WARNING",
                        vuln_type="OPEN_REDIRECT",
                        description=(
                            f"Open redirect detected via parameter '{param_name}'. "
                            f"The application redirects to attacker-controlled URLs. "
                            f"Redirect location: {location}"
                        ),
                        rule_id="open-redirect",
                        cwe_id="CWE-601",
                        confidence=0.85,
                        code_snippet=(
                            f"Request: GET {test_url}\n"
                            f"Response: HTTP {resp.status_code}\n"
                            f"Location: {location}"
                        ),
                        raw={
                            "url": url,
                            "param": param_name,
                            "redirect_to": location,
                        },
                    ))
                    return findings

        return findings

    def _check_stored_xss(self, url: str) -> list[RawFinding]:
        """
        Attempt simple stored-XSS probe on discovered form fields.
        
        Optimization: Cache page content to avoid redundant fetches.
        """
        findings: list[RawFinding] = []
        payload = '<script>alert(1)</script>'

        try:
            resp = self._fetch(url)
            body = resp.text[:50_000]
            input_pattern = re.compile(
                r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
                re.IGNORECASE,
            )
            form_action_pattern = re.compile(
                r'<form[^>]*action\s*=\s*["\']([^"\']*)["\'][^>]*>',
                re.IGNORECASE,
            )
            field_names = input_pattern.findall(body)
            form_actions = form_action_pattern.findall(body)

            if not field_names:
                return findings

            action_url = urljoin(url, form_actions[0]) if form_actions else url
            form_data = {name: payload for name in field_names[:5]}
            post_resp = self._post(action_url, data=form_data)
            if post_resp is None:
                return findings

            # Check if payload was stored and reflected in POST response
            # Optimization: Only make extra verify request if POST doesn't contain it
            if payload in post_resp.text:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="ERROR",
                    vuln_type="XSS",
                    description=(
                        "Potential stored XSS detected. XSS payload submitted via form "
                        "appeared in the response immediately after submission."
                    ),
                    rule_id="xss-stored-probe",
                    cwe_id="CWE-79",
                    confidence=0.75,
                    code_snippet=(
                        f"POST {action_url}\n"
                        f"Form fields: {field_names[:5]}\n"
                        f"Payload: {payload}\n"
                        "Payload reflected in response"
                    ),
                    raw={"url": url, "action": action_url, "payload": payload},
                ))
            elif self._within_budget():
                # Only verify if within budget - try re-fetching page
                try:
                    verify_resp = self._fetch(url)
                    if payload in verify_resp.text:
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="ERROR",
                            vuln_type="XSS",
                            description=(
                                "Potential stored XSS detected. XSS payload submitted via form "
                                "appeared in a subsequent page response."
                            ),
                            rule_id="xss-stored-probe",
                            cwe_id="CWE-79",
                            confidence=0.75,
                            code_snippet=(
                                f"POST {action_url}\n"
                                f"Form fields: {field_names[:5]}\n"
                                f"Payload: {payload}\n"
                                "Payload reflected after submit"
                            ),
                            raw={"url": url, "action": action_url, "payload": payload},
                        ))
                except Exception:
                    pass
        except _BudgetExceededError:
            return findings
        except Exception as e:
            logger.debug("Stored XSS probe failed: %s", e)

        return findings

    def _check_ssrf(self, url: str) -> list[RawFinding]:
        """Probe URL parameters for SSRF behavior using internal endpoint payloads."""
        findings: list[RawFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        test_params = list(params.keys()) if params else []
        for p in SSRF_PARAMS:
            if p not in test_params:
                test_params.append(p)

        # Optimization: Skip low-value parameters
        test_params = [
            p for p in test_params[:10]
            if not self._is_low_value_param(p)
        ]

        for param_name in test_params:
            if not self._within_budget():
                return findings
            for payload in SSRF_PROBES[:2]:  # Reduced from 3 to 2
                if not self._within_budget():
                    return findings
                candidate = dict(params) if params else {}
                candidate[param_name] = [payload]
                query_string = urlencode(candidate, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, "",
                ))
                try:
                    resp = self._fetch(test_url)
                    body = resp.text[:4000].lower()
                    ssrf_indicators = [
                        "169.254.169.254",
                        "meta-data",
                        "connection refused",
                        "unable to resolve host",
                        "localhost",
                    ]
                    if any(marker in body for marker in ssrf_indicators) or resp.status_code >= 500:
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="ERROR",
                            vuln_type="SSRF",
                            description=(
                                f"Potential SSRF detected via parameter '{param_name}'. "
                                "Application appears to process attacker-controlled URLs."
                            ),
                            rule_id="ssrf-probe",
                            cwe_id="CWE-918",
                            confidence=0.7,
                            code_snippet=(
                                f"Request: GET {test_url}\n"
                                f"Payload: {payload}\n"
                                f"Status: {resp.status_code}\n"
                                f"Response excerpt: {resp.text[:250]}"
                            ),
                            raw={"url": url, "param": param_name, "payload": payload},
                        ))
                        return findings
                except _BudgetExceededError:
                    return findings
                except Exception:
                    continue

        return findings

    def _check_path_traversal(self, url: str) -> list[RawFinding]:
        """Probe file/path parameters for directory traversal."""
        findings: list[RawFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        candidate_params = [k for k in params.keys() if any(x in k.lower() for x in ["file", "path", "template", "page", "download"])]
        
        # Optimization: Skip low-value parameters if no obvious file params found
        if not candidate_params:
            candidate_params = [
                "file", "path", "page", "template"
            ]
        else:
            candidate_params = [
                p for p in candidate_params[:8]
                if not self._is_low_value_param(p)
            ]

        for param_name in candidate_params[:6]:
            if not self._within_budget():
                return findings
            # Optimization: Only test Unix path first (most common)
            for payload in PATH_TRAVERSAL_PAYLOADS[:1]:
                if not self._within_budget():
                    return findings
                candidate = dict(params) if params else {}
                candidate[param_name] = [payload]
                query_string = urlencode(candidate, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, "",
                ))
                try:
                    resp = self._fetch(test_url)
                    body = resp.text[:5000]
                    if ("root:x:" in body) or ("[extensions]" in body.lower()):
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="ERROR",
                            vuln_type="PATH_TRAVERSAL",
                            description=(
                                f"Path traversal confirmed via parameter '{param_name}'. "
                                "Sensitive file content was returned in the response."
                            ),
                            rule_id="path-traversal-probe",
                            cwe_id="CWE-22",
                            confidence=0.9,
                            code_snippet=(
                                f"Request: GET {test_url}\n"
                                f"Payload: {payload}\n"
                                f"Response excerpt: {body[:250]}"
                            ),
                            raw={"url": url, "param": param_name, "payload": payload},
                        ))
                        return findings
                    # If Unix failed, try Windows payload
                    elif payload == PATH_TRAVERSAL_PAYLOADS[0] and not any(x in body for x in ["root:", "extensions"]):
                        if self._within_budget() and len(PATH_TRAVERSAL_PAYLOADS) > 1:
                            # Try Windows payload
                            candidate = dict(params) if params else {}
                            candidate[param_name] = [PATH_TRAVERSAL_PAYLOADS[1]]
                            query_string = urlencode(candidate, doseq=True)
                            test_url = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, query_string, "",
                            ))
                            try:
                                resp = self._fetch(test_url)
                                body = resp.text[:5000]
                                if "[extensions]" in body.lower():
                                    findings.append(RawFinding(
                                        tool_source=self.name,
                                        file=url,
                                        line_start=0,
                                        severity="ERROR",
                                        vuln_type="PATH_TRAVERSAL",
                                        description=(
                                            f"Path traversal confirmed via parameter '{param_name}'. "
                                            "Sensitive file content was returned in the response."
                                        ),
                                        rule_id="path-traversal-probe",
                                        cwe_id="CWE-22",
                                        confidence=0.9,
                                        code_snippet=(
                                            f"Request: GET {test_url}\n"
                                            f"Payload: {PATH_TRAVERSAL_PAYLOADS[1]}\n"
                                            f"Response excerpt: {body[:250]}"
                                        ),
                                        raw={"url": url, "param": param_name, "payload": PATH_TRAVERSAL_PAYLOADS[1]},
                                    ))
                                    return findings
                            except Exception:
                                continue
                except _BudgetExceededError:
                    return findings
                except Exception:
                    continue

        return findings

    def _check_xxe(self, url: str) -> list[RawFinding]:
        """Probe XML-like endpoints for XXE via malicious XML payload."""
        findings: list[RawFinding] = []
        parsed = urlparse(url)
        xmlish = any(token in parsed.path.lower() for token in ["xml", "import", "upload", "feed", "soap", "api"])
        if not xmlish:
            return findings

        try:
            self._before_request()
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = client.post(
                    url,
                    content=XXE_PROBE_XML,
                    headers={
                        "Content-Type": "application/xml",
                        "User-Agent": "SecuritySignalEngine/1.0 (Security Scanner)",
                    },
                )

            body = resp.text[:5000]
            indicators = ["root:x:", "xxe", "doctype", "entity", "system identifier"]
            if any(marker in body.lower() for marker in indicators) or resp.status_code >= 500:
                findings.append(RawFinding(
                    tool_source=self.name,
                    file=url,
                    line_start=0,
                    severity="ERROR",
                    vuln_type="XXE",
                    description=(
                        "Potential XXE detected. XML parser behavior indicates external "
                        "entity processing may be enabled."
                    ),
                    rule_id="xxe-probe",
                    cwe_id="CWE-611",
                    confidence=0.7,
                    code_snippet=(
                        f"POST {url} (application/xml)\n"
                        f"Payload: {XXE_PROBE_XML[:160]}...\n"
                        f"Response excerpt: {body[:250]}"
                    ),
                    raw={"url": url, "status": resp.status_code},
                ))
        except _BudgetExceededError:
            return findings
        except Exception as e:
            logger.debug("XXE probe failed for %s: %s", url, e)

        return findings

    def _check_idor(self, urls: list[str]) -> list[RawFinding]:
        """Probe numeric object identifiers for authorization bypass patterns."""
        findings: list[RawFinding] = []

        for url in urls:
            parsed = urlparse(url)
            match = IDOR_PATH_RE.match(parsed.path)
            if not match:
                continue

            base_id = int(match.group("id"))
            for candidate_id in [base_id + 1, max(base_id - 1, 1)]:
                if not self._within_budget():
                    return findings
                new_path = f"{match.group('prefix')}{candidate_id}{match.group('suffix')}"
                probe_url = urlunparse((
                    parsed.scheme, parsed.netloc, new_path,
                    parsed.params, parsed.query, "",
                ))
                try:
                    original_resp = self._fetch(url)
                    probe_resp = self._fetch(probe_url)
                    original_len = len(original_resp.text)
                    probe_len = len(probe_resp.text)

                    if probe_resp.status_code == 200 and abs(probe_len - original_len) < 250:
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="WARNING",
                            vuln_type="IDOR",
                            description=(
                                "Potential IDOR detected. Adjacent object identifiers were accessible "
                                "with similar response structure."
                            ),
                            rule_id="idor-pattern-probe",
                            cwe_id="CWE-639",
                            confidence=0.6,
                            code_snippet=(
                                f"Original URL: {url} ({original_resp.status_code}, len={original_len})\n"
                                f"Probed URL: {probe_url} ({probe_resp.status_code}, len={probe_len})"
                            ),
                            raw={"url": url, "probe_url": probe_url},
                        ))
                        return findings
                except _BudgetExceededError:
                    return findings
                except Exception:
                    continue

        return findings

    def _check_directory_listing(self, base_url: str) -> list[RawFinding]:
        """Check for open directory listings on common paths."""
        findings: list[RawFinding] = []
        test_paths = ["/", "/images/", "/uploads/", "/static/", "/files/", "/assets/"]

        for path in test_paths:
            if not self._within_budget():
                return findings
            full_url = urljoin(base_url, path)
            try:
                resp = self._fetch(full_url)
                body = resp.text[:3000].lower()

                # Common directory listing indicators
                if (
                    "index of" in body
                    or "directory listing" in body
                    or "<title>index of" in body
                    or "parent directory" in body
                ):
                    findings.append(RawFinding(
                        tool_source=self.name,
                        file=full_url,
                        line_start=0,
                        severity="WARNING",
                        vuln_type="INFORMATION_DISCLOSURE",
                        description=(
                            f"Directory listing enabled at {path}. "
                            "An attacker can browse all files in this directory, "
                            "potentially discovering sensitive files, backups, "
                            "or application source code."
                        ),
                        rule_id="directory-listing",
                        cwe_id="CWE-548",
                        confidence=0.90,
                        code_snippet=f"GET {path} → Directory listing detected",
                        raw={
                            "url": full_url,
                            "path": path,
                            "check": "directory_listing",
                        },
                    ))
            except _BudgetExceededError:
                return findings
            except Exception:
                continue

        return findings

    def _check_dangerous_methods(self, url: str) -> list[RawFinding]:
        """Test for dangerous HTTP methods (PUT, DELETE, TRACE)."""
        findings: list[RawFinding] = []
        dangerous_methods = ["PUT", "DELETE", "TRACE"]

        try:
            # Use OPTIONS to discover allowed methods
            self._before_request()
            with httpx.Client(
                timeout=5, follow_redirects=False, verify=False
            ) as client:
                resp = client.options(url, headers={
                    "User-Agent": "SecuritySignalEngine/1.0 (Security Scanner)"
                })

            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                allowed = [m.strip().upper() for m in allow_header.split(",")]
                for method in dangerous_methods:
                    if method in allowed:
                        findings.append(RawFinding(
                            tool_source=self.name,
                            file=url,
                            line_start=0,
                            severity="WARNING",
                            vuln_type="MISSING_AUTH",
                            description=(
                                f"Dangerous HTTP method '{method}' is enabled. "
                                f"This could allow attackers to modify or delete "
                                f"resources on the server."
                            ),
                            rule_id=f"dangerous-method-{method.lower()}",
                            cwe_id="CWE-749",
                            confidence=0.75,
                            code_snippet=f"Allow: {allow_header}",
                            raw={
                                "url": url,
                                "method": method,
                                "allow": allow_header,
                            },
                        ))
        except _BudgetExceededError:
            return findings
        except Exception:
            pass

        return findings
