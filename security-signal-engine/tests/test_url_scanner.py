"""
Tests for URL scanner budget behavior.
"""

from urllib.parse import parse_qs, urlparse

from src.scanners.url_scanner import URLScanner


class _FakeResponse:
    def __init__(self, text: str = "ok", status_code: int = 200):
        self.text = text
        self.status_code = status_code


def test_ssrf_probe_stops_when_budget_exhausted(monkeypatch):
    """SSRF probing should stop quickly once request budget is reached."""
    scanner = URLScanner(max_requests_per_scan=2, max_scan_seconds=60)
    scanner._scan_deadline = 10**12

    call_counter = {"count": 0}

    def fake_fetch(url: str, **kwargs):
        call_counter["count"] += 1
        scanner._before_request()
        return _FakeResponse(text="ok", status_code=200)

    monkeypatch.setattr(scanner, "_fetch", fake_fetch)

    findings = scanner._check_ssrf("https://example.com")

    assert findings == []
    # Should stop immediately once budget is exhausted.
    assert call_counter["count"] <= 3


def test_sqli_probe_respects_budget(monkeypatch):
    """SQLi probing should not continue iterating after budget exhaustion."""
    scanner = URLScanner(max_requests_per_scan=1, max_scan_seconds=60)
    scanner._scan_deadline = 10**12

    call_counter = {"count": 0}

    def fake_fetch(url: str, **kwargs):
        call_counter["count"] += 1
        scanner._before_request()
        return _FakeResponse(text="normal body", status_code=200)

    monkeypatch.setattr(scanner, "_fetch", fake_fetch)

    parsed = urlparse("https://example.com/search?q=test")
    params = parse_qs(parsed.query, keep_blank_values=True)
    findings = scanner._sqli_probe_params("https://example.com/search?q=test", parsed, params)

    assert findings == []
    assert call_counter["count"] <= 2
