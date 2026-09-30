"""
Scanner orchestrator — manages scanner lifecycle and aggregates results.

Reads configuration to determine which scanners to run, invokes each
one, and collects all raw findings into a single list.

Supports both local directory targets (Semgrep) and URL targets
(built-in URL scanner). Includes a plugin system for custom scanners.
"""

from __future__ import annotations

import logging
import subprocess
import time
from urllib.parse import urlparse

from src.models.schemas import RawFinding, ScanConfig
from src.scanners.base import BaseScanner, ScannerError
from src.scanners.semgrep import SemgrepScanner
from src.scanners.url_scanner import URLScanner
from src.scanners.plugin_manager import PluginManager

logger = logging.getLogger(__name__)

# Registry of available scanner adapters (file-based)
_SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "semgrep": SemgrepScanner,
}


def is_url_target(target: str) -> bool:
    """Check if the target is a URL (starts with http:// or https://)."""
    parsed = urlparse(target)
    return parsed.scheme in ("http", "https")


class ScannerOrchestrator:
    """
    Orchestrates the execution of one or more security scanners.

    Automatically detects whether the target is a URL or a local path:
    - URLs → built-in URL scanner (security headers, SSL, cookies, etc.)
    - Local paths → file-based scanners (Semgrep, plugins, etc.)
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._scanners: list[BaseScanner] = []
        # Initialize URL scanner with configured parameters + new subsystems
        self._url_scanner = URLScanner(
            timeout=config.url_scanner.timeout,
            max_crawl_urls=config.url_scanner.max_crawl_urls,
            max_active_probe_urls=config.url_scanner.max_active_probe_urls,
            max_requests_per_scan=config.url_scanner.max_requests_per_scan,
            max_scan_seconds=config.url_scanner.max_scan_seconds,
            # Pass new subsystem configs
            rate_limiter_config=config.rate_limiter.model_dump(),
            crawler_config=config.crawler.model_dump(),
            traffic_store_config=config.traffic_store.model_dump(),
            oast_config=config.oast.model_dump(),
        )
        # Initialize plugin manager
        self._plugin_manager = PluginManager(
            plugin_dir=config.plugins.plugin_dir,
            enabled_plugins=config.plugins.enabled_plugins or None,
            disabled_plugins=config.plugins.disabled_plugins,
        )
        self._init_scanners()

    def _init_scanners(self) -> None:
        """Initialize file-based scanner instances and load plugins."""
        # Built-in scanners
        for scanner_name in self.config.scanners_enabled:
            if scanner_name == "url-scanner":
                # URL scanner is built-in and initialized separately.
                continue

            scanner_cls = _SCANNER_REGISTRY.get(scanner_name)
            if scanner_cls is None:
                logger.warning("Unknown scanner: %s (skipping)", scanner_name)
                continue

            # Pass scanner-specific config
            if scanner_name == "semgrep":
                scanner = scanner_cls(config=self.config.semgrep)
            else:
                scanner = scanner_cls()

            if scanner.is_available():
                self._scanners.append(scanner)
                logger.info("Scanner '%s' initialized", scanner_name)
            else:
                logger.warning(
                    "Scanner '%s' is not available on this system (skipping)",
                    scanner_name,
                )

        # Load plugins (solves Caido's immature ecosystem limitation)
        if self.config.plugins.enabled:
            plugins = self._plugin_manager.discover_and_load()
            for plugin in plugins:
                if plugin.is_available():
                    self._scanners.append(plugin)
                    logger.info("Plugin scanner '%s' loaded", plugin.name)
                else:
                    logger.warning(
                        "Plugin '%s' is not available (skipping)",
                        plugin.name,
                    )

    def run(self, target: str) -> list[RawFinding]:
        """
        Run scanners against the target.

        If the target is a URL, uses the built-in URL scanner.
        If the target is a local path, uses configured file-based scanners.

        Args:
            target: URL or path to scan.

        Returns:
            Aggregated list of raw findings from all scanners.
        """
        if is_url_target(target):
            return self._run_url_scan(target)
        return self._run_file_scan(target)

    def _run_url_scan(self, target: str) -> list[RawFinding]:
        """Run the URL scanner against a web target."""
        if "url-scanner" not in self.config.scanners_enabled:
            logger.warning("URL scanner disabled in config (scanners_enabled)")
            return []

        logger.info("Target is a URL — using built-in URL scanner")
        start = time.time()

        try:
            findings = self._url_scanner.run(target)
            duration = time.time() - start
            logger.info(
                "URL scanner completed in %.2fs — %d findings",
                duration,
                len(findings),
            )
            return findings
        except ScannerError as e:
            logger.error("URL scanner failed: %s", e)
            return [RawFinding(
                tool_source="url-scanner",
                file=target,
                line_start=0,
                severity="ERROR",
                vuln_type="SCAN_INCOMPLETE",
                description=(
                    "The target could not be reached reliably, so the website was not fully assessed. "
                    "This is not evidence that the target is secure. Verify DNS, protocol, port, "
                    "firewall, TLS, and application availability, then rerun the scan."
                ),
                rule_id="scan-target-unreachable",
                cwe_id=None,
                confidence=1.0,
                code_snippet=f"Target: {target}\nScanner error: {e}",
                raw={"target": target, "error": str(e), "scan_complete": False},
            )]
        except Exception as e:
            logger.error("Unexpected error in URL scanner: %s", e)
            return []

    def _run_file_scan(self, target: str) -> list[RawFinding]:
        """Run file-based scanners against a local directory."""
        all_findings: list[RawFinding] = []

        if not self._scanners:
            logger.error("No scanners available. Install at least one scanner.")
            return all_findings

        for scanner in self._scanners:
            scanner_name = scanner.name
            logger.info("Running scanner: %s", scanner_name)
            start = time.time()

            try:
                findings = scanner.run(target)
                duration = time.time() - start
                logger.info(
                    "Scanner '%s' completed in %.2fs — %d findings",
                    scanner_name,
                    duration,
                    len(findings),
                )
                all_findings.extend(findings)
            except ScannerError as e:
                logger.error("Scanner '%s' failed: %s", scanner_name, e)
            except Exception as e:
                logger.error(
                    "Unexpected error running scanner '%s': %s",
                    scanner_name,
                    e,
                )

        logger.info("Total raw findings from all scanners: %d", len(all_findings))
        return all_findings

    def scanners_used_for_target(self, target: str) -> list[str]:
        """Return scanner names used for a given target."""
        if is_url_target(target):
            if "url-scanner" not in self.config.scanners_enabled:
                return []
            return [self._url_scanner.name]
        return [scanner.name for scanner in self._scanners]

    def scanner_versions_for_target(self, target: str) -> dict[str, str]:
        """Return scanner version map for the scanners used for a target."""
        versions: dict[str, str] = {}
        scanner_names = self.scanners_used_for_target(target)

        for scanner_name in scanner_names:
            if scanner_name == "semgrep":
                versions[scanner_name] = self._semgrep_version()
            elif scanner_name == "url-scanner":
                versions[scanner_name] = "builtin-1.0"
            else:
                versions[scanner_name] = "unknown"

        return versions

    def _semgrep_version(self) -> str:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version = (result.stdout or result.stderr).strip()
            return version or "unknown"
        except Exception:
            return "unknown"
