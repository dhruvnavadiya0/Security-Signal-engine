"""
Smart Crawler with Loop Detection — state-machine-aware web crawling.

Solves the technical limitation found in OWASP ZAP where traditional
and AJAX spiders get stuck in infinite loops on dynamic sites.

Strategy:
  - URL structural similarity: Clusters URLs by their path structure,
    ignoring numeric IDs and UUIDs. Detects when the crawler is visiting
    structurally identical pages (e.g., /product/1, /product/2, ...).
  - Depth limiting: Prevents crawling beyond a configurable depth.
  - Structural hashing: Uses path template fingerprints to identify
    duplicate page structures even when URLs differ.
  - Budget awareness: Integrates with the adaptive rate limiter.

This replaces URLScanner._crawl_site() with a smarter implementation.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import defaultdict
from urllib.parse import urlparse, urljoin, urlunparse

import httpx

logger = logging.getLogger(__name__)


# Patterns for normalizing URL path segments
_NUMERIC_SEGMENT = re.compile(r'^\d+$')
_UUID_SEGMENT = re.compile(
    r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$',
    re.IGNORECASE,
)
_HEX_SEGMENT = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)
_HASH_SEGMENT = re.compile(r'^[0-9a-f]{32,64}$', re.IGNORECASE)

# Link extraction pattern
_HREF_PATTERN = re.compile(
    r'(?:href|action)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Low-value URL patterns to skip
_SKIP_PATTERNS = [
    "/logout", "/signout", "/sign-out", "/exit",
    "/download", "/print", "/export",
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".pdf", ".doc", ".zip", ".exe", ".woff", ".woff2", ".ttf",
    "/static/", "/assets/", "/cdn/", "/images/", "/fonts/",
    "/wp-includes/", "/wp-content/themes/",
]


def _normalize_path_structure(path: str) -> str:
    """
    Normalize a URL path by replacing dynamic segments with placeholders.

    Examples:
        /product/42/reviews     → /product/{N}/reviews
        /user/abc123-def456     → /user/{UUID}
        /api/v1/items/99        → /api/v1/items/{N}

    This allows us to detect structural similarity between URLs
    that differ only in their dynamic parameters.
    """
    segments = path.strip("/").split("/")
    normalized = []

    for seg in segments:
        if not seg:
            continue
        if _UUID_SEGMENT.match(seg):
            normalized.append("{UUID}")
        elif _HASH_SEGMENT.match(seg):
            normalized.append("{HASH}")
        elif _NUMERIC_SEGMENT.match(seg):
            normalized.append("{N}")
        elif _HEX_SEGMENT.match(seg):
            normalized.append("{HEX}")
        else:
            normalized.append(seg.lower())

    return "/" + "/".join(normalized)


def _structural_hash(normalized_path: str) -> str:
    """Compute a short hash of a normalized path structure."""
    return hashlib.md5(normalized_path.encode()).hexdigest()[:12]


class SmartCrawler:
    """
    State-machine-aware web crawler with loop detection.

    Instead of blindly following links, this crawler:
    1. Normalizes URL structures to detect duplicates.
    2. Tracks how many times each URL structure has been seen.
    3. Stops crawling a structure after a configurable threshold.
    4. Enforces depth limits to prevent unbounded crawling.
    5. Skips low-value endpoints (static assets, logout, etc.).
    """

    def __init__(
        self,
        max_urls: int = 20,
        max_depth: int = 5,
        loop_threshold: int = 3,
        timeout: int = 10,
        max_response_bytes: int = 2_000_000,
    ):
        """
        Args:
            max_urls: Maximum unique URLs to crawl.
            max_depth: Maximum link-following depth from start URL.
            loop_threshold: Maximum URLs with the same structural
                pattern before we stop following that pattern.
            timeout: HTTP request timeout in seconds.
            max_response_bytes: Skip responses larger than this.
        """
        self.max_urls = max_urls
        self.max_depth = max_depth
        self.loop_threshold = loop_threshold
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

        # State tracking
        self._visited: set[str] = set()
        self._structure_counts: dict[str, int] = defaultdict(int)
        self._structure_examples: dict[str, list[str]] = defaultdict(list)
        self._request_count: int = 0

    def crawl(
        self,
        base_url: str,
        start_url: str,
        budget_check: callable = None,
        request_hook: callable = None,
    ) -> list[str]:
        """
        Crawl same-origin links from the start URL with loop detection.

        Args:
            base_url: The base URL (scheme + netloc) for same-origin checking.
            start_url: The URL to start crawling from.
            budget_check: Optional callable that returns False if budget
                is exhausted (integrates with URLScanner._within_budget).
            request_hook: Optional callable to invoke before each request
                (integrates with URLScanner._before_request).

        Returns:
            List of unique discovered URLs (excluding the start URL).
        """
        self._visited.clear()
        self._structure_counts.clear()
        self._structure_examples.clear()
        self._request_count = 0

        parsed_base = urlparse(base_url)
        # BFS queue: (url, depth)
        queue: list[tuple[str, int]] = [(start_url, 0)]

        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            while queue and len(self._visited) < self.max_urls:
                if budget_check and not budget_check():
                    logger.info("Smart crawler: budget exhausted, stopping.")
                    break

                current_url, depth = queue.pop(0)

                if current_url in self._visited:
                    continue

                if depth > self.max_depth:
                    continue

                # Check structural similarity / loop detection
                parsed_current = urlparse(current_url)
                normalized = _normalize_path_structure(parsed_current.path)
                struct_hash = _structural_hash(normalized)

                if self._structure_counts[struct_hash] >= self.loop_threshold:
                    logger.debug(
                        "Smart crawler: skipping %s (loop detected, "
                        "structure '%s' seen %d times)",
                        current_url,
                        normalized,
                        self._structure_counts[struct_hash],
                    )
                    continue

                # Skip low-value endpoints
                if self._should_skip(current_url):
                    continue

                # Mark as visited and update structure tracking
                self._visited.add(current_url)
                self._structure_counts[struct_hash] += 1
                self._structure_examples[struct_hash].append(current_url)

                # Fetch the page
                try:
                    if request_hook:
                        request_hook()
                    self._request_count += 1

                    resp = client.get(current_url, headers={
                        "User-Agent": "SecuritySignalEngine/1.0 (Security Scanner)"
                    })

                    # Skip large responses
                    if len(resp.content) > self.max_response_bytes:
                        continue

                    # Extract and queue new links
                    for link in self._extract_links(
                        resp.text, parsed_base, current_url
                    ):
                        if link not in self._visited:
                            queue.append((link, depth + 1))

                except Exception as e:
                    logger.debug("Smart crawler: failed to fetch %s: %s", current_url, e)

        self._visited.discard(start_url)

        # Log crawl summary with loop detection stats
        loops_detected = sum(
            1 for count in self._structure_counts.values()
            if count >= self.loop_threshold
        )
        logger.info(
            "Smart crawl complete: %d URLs visited, %d unique structures, "
            "%d loops detected, %d requests made",
            len(self._visited),
            len(self._structure_counts),
            loops_detected,
            self._request_count,
        )

        return list(self._visited)[:self.max_urls]

    def _should_skip(self, url: str) -> bool:
        """Check if a URL should be skipped (low-value endpoint)."""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in _SKIP_PATTERNS)

    def _extract_links(
        self, body: str, parsed_base, from_url: str
    ) -> list[str]:
        """Extract same-origin links from HTML content."""
        discovered: set[str] = set()

        for match in _HREF_PATTERN.finditer(body[:100_000]):
            href = match.group(1).strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            full_url = urljoin(from_url, href)
            parsed = urlparse(full_url)

            if parsed.netloc != parsed_base.netloc:
                continue

            # Clean URL (remove fragment)
            clean = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                "",  # No fragment
            ))
            discovered.add(clean)

        return list(discovered)

    def get_loop_report(self) -> dict[str, dict]:
        """
        Get a report of detected loop patterns.

        Returns a dict mapping structural patterns to their stats,
        useful for the scan report.
        """
        report = {}
        for struct_hash, count in self._structure_counts.items():
            if count >= 2:  # Only report patterns seen 2+ times
                examples = self._structure_examples.get(struct_hash, [])
                report[struct_hash] = {
                    "count": count,
                    "is_loop": count >= self.loop_threshold,
                    "examples": examples[:3],  # First 3 examples
                }
        return report
