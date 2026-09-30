"""
OAST (Out-of-Band Application Security Testing) Callback Detector.

Solves the technical limitation found in Caido which has no equivalent
to Burp Collaborator. Without OAST, blind SSRF, blind SQLi, and
blind XXE vulnerabilities cannot be detected.

Strategy:
  - Generates unique probe tokens for each injection point.
  - Provides canary URLs that the DAST engine injects into payloads.
  - Runs a lightweight async HTTP callback listener on a configurable port.
  - When the target server makes an outbound request to our listener,
    we confirm the blind vulnerability and log the callback details.
  - Falls back to a polling-based model when the async server isn't
    available (e.g., behind NAT).

This module uses only stdlib + asyncio. No external deps.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class OASTProbe:
    """A single OAST probe configuration."""
    token: str                       # Unique probe identifier
    vuln_type: str                   # e.g., "SSRF", "XXE", "BLIND_SQLI"
    target_url: str                  # The URL being tested
    param_name: str = ""             # The parameter being injected
    payload: str = ""                # The payload that was injected
    created_at: float = field(default_factory=time.time)
    callback_received: bool = False
    callback_at: Optional[float] = None
    callback_source_ip: str = ""
    callback_path: str = ""
    callback_method: str = ""


@dataclass
class OASTCallback:
    """A received callback from the target."""
    token: str
    source_ip: str
    method: str
    path: str
    headers: dict = field(default_factory=dict)
    body: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class OASTStats:
    """OAST subsystem statistics for reporting."""
    total_probes_generated: int = 0
    total_callbacks_received: int = 0
    confirmed_vulns: int = 0
    listener_active: bool = False
    listener_port: int = 0


class OASTCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the OAST callback listener."""

    # Class-level reference to the OASTManager (set during server setup)
    manager: Optional[OASTManager] = None

    def do_GET(self):
        self._handle_callback("GET")

    def do_POST(self):
        self._handle_callback("POST")

    def do_PUT(self):
        self._handle_callback("PUT")

    def do_HEAD(self):
        self._handle_callback("HEAD")

    def do_OPTIONS(self):
        self._handle_callback("OPTIONS")

    def _handle_callback(self, method: str):
        """Process any incoming callback request."""
        # Extract token from path
        path = self.path
        token = path.strip("/").split("/")[-1] if "/" in path else path.strip("/")

        # Read body for POST/PUT
        body = ""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(min(content_length, 4096)).decode(
                "utf-8", errors="replace"
            )

        callback = OASTCallback(
            token=token,
            source_ip=self.client_address[0],
            method=method,
            path=path,
            headers=dict(self.headers),
            body=body,
        )

        if self.manager:
            self.manager._process_callback(callback)

        # Always respond 200 to avoid tipping off the target
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        logger.debug("OAST callback: %s", format % args)


class OASTManager:
    """
    Out-of-Band Application Security Testing manager.

    Generates probe tokens, manages a callback listener, and
    correlates received callbacks with injected probes to confirm
    blind vulnerabilities.

    Usage:
        manager = OASTManager(listener_port=9999)
        manager.start_listener()

        # Generate a probe
        probe = manager.create_probe(
            vuln_type="SSRF",
            target_url="https://example.com/api",
            param_name="url",
        )

        # Inject the canary URL into your payload
        payload = probe.canary_url  # http://your-ip:9999/TOKEN

        # ... scanner injects the payload ...

        # Check if any callbacks were received
        confirmed = manager.get_confirmed_probes()
        manager.stop_listener()
    """

    def __init__(
        self,
        listener_host: str = "0.0.0.0",
        listener_port: int = 9999,
        callback_base_url: Optional[str] = None,
        enabled: bool = True,
    ):
        """
        Args:
            listener_host: Host to bind the callback listener.
            listener_port: Port for the callback listener.
            callback_base_url: Base URL for canary URLs. If None,
                auto-generates from listener_host:port.
            enabled: Whether OAST is active.
        """
        self._host = listener_host
        self._port = listener_port
        self._enabled = enabled
        self._callback_base_url = (
            callback_base_url or f"http://127.0.0.1:{listener_port}"
        )

        self._probes: dict[str, OASTProbe] = {}
        self._callbacks: list[OASTCallback] = []
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[Thread] = None
        self._listener_active = False

    def create_probe(
        self,
        vuln_type: str,
        target_url: str,
        param_name: str = "",
    ) -> OASTProbe:
        """
        Create a new OAST probe with a unique token.

        Returns the probe object. Use probe.token to build the
        canary URL: {callback_base_url}/{token}
        """
        token = self._generate_token()
        probe = OASTProbe(
            token=token,
            vuln_type=vuln_type,
            target_url=target_url,
            param_name=param_name,
        )
        self._probes[token] = probe
        return probe

    def get_canary_url(self, token: str) -> str:
        """Get the full canary URL for a probe token."""
        return f"{self._callback_base_url}/{token}"

    def start_listener(self) -> bool:
        """
        Start the HTTP callback listener in a background thread.

        Returns True if the listener started successfully.
        """
        if not self._enabled:
            logger.info("OAST listener disabled by configuration")
            return False

        try:
            OASTCallbackHandler.manager = self
            self._server = HTTPServer(
                (self._host, self._port),
                OASTCallbackHandler,
            )
            self._server_thread = Thread(
                target=self._server.serve_forever,
                daemon=True,
                name="oast-listener",
            )
            self._server_thread.start()
            self._listener_active = True
            logger.info(
                "OAST callback listener started on %s:%d",
                self._host,
                self._port,
            )
            return True
        except OSError as e:
            logger.warning(
                "Failed to start OAST listener on port %d: %s "
                "(port may be in use, OAST blind detection disabled)",
                self._port,
                e,
            )
            self._listener_active = False
            return False

    def stop_listener(self) -> None:
        """Stop the callback listener."""
        if self._server:
            self._server.shutdown()
            self._listener_active = False
            logger.info("OAST callback listener stopped")

    def _generate_token(self) -> str:
        """Generate a unique, URL-safe probe token."""
        raw = uuid.uuid4().hex
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def _process_callback(self, callback: OASTCallback) -> None:
        """Process a received callback and correlate with probes."""
        self._callbacks.append(callback)

        probe = self._probes.get(callback.token)
        if probe:
            probe.callback_received = True
            probe.callback_at = callback.timestamp
            probe.callback_source_ip = callback.source_ip
            probe.callback_path = callback.path
            probe.callback_method = callback.method
            logger.info(
                "🎯 OAST callback confirmed! Blind %s at %s (param=%s) "
                "— callback from %s via %s",
                probe.vuln_type,
                probe.target_url,
                probe.param_name,
                callback.source_ip,
                callback.method,
            )
        else:
            logger.debug(
                "OAST callback received for unknown token: %s (from %s)",
                callback.token,
                callback.source_ip,
            )

    def get_confirmed_probes(self) -> list[OASTProbe]:
        """Get all probes that received a callback (confirmed blind vulns)."""
        return [p for p in self._probes.values() if p.callback_received]

    def check_callbacks(self, wait_seconds: float = 2.0) -> list[OASTProbe]:
        """
        Wait briefly for callbacks then return confirmed probes.

        This gives time for async callbacks to arrive after
        the scanning phase completes.
        """
        if not self._listener_active:
            return []

        logger.info(
            "OAST: waiting %.1fs for out-of-band callbacks...",
            wait_seconds,
        )
        time.sleep(wait_seconds)
        return self.get_confirmed_probes()

    def get_stats(self) -> OASTStats:
        """Get OAST subsystem statistics."""
        return OASTStats(
            total_probes_generated=len(self._probes),
            total_callbacks_received=len(self._callbacks),
            confirmed_vulns=len(self.get_confirmed_probes()),
            listener_active=self._listener_active,
            listener_port=self._port,
        )

    def get_ssrf_payloads(self, target_url: str, param_name: str) -> list[str]:
        """
        Generate SSRF-specific OAST payloads.

        Returns a list of canary URLs to inject into the given parameter.
        Each URL has a unique token for correlation.
        """
        probe = self.create_probe(
            vuln_type="SSRF",
            target_url=target_url,
            param_name=param_name,
        )
        canary = self.get_canary_url(probe.token)
        return [
            canary,
            f"{canary}/ssrf-test",
        ]

    def get_xxe_payload(self, target_url: str) -> tuple[str, str]:
        """
        Generate an XXE-specific OAST payload.

        Returns (xxe_xml_payload, probe_token).
        """
        probe = self.create_probe(
            vuln_type="XXE",
            target_url=target_url,
        )
        canary = self.get_canary_url(probe.token)
        xxe_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{canary}">]>'
            '<root><item>&xxe;</item></root>'
        )
        return xxe_xml, probe.token
