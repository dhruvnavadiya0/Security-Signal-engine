"""
Tests for the Semgrep scanner adapter.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.models.schemas import SemgrepConfig
from src.scanners.base import ScannerError
from src.scanners.orchestrator import ScannerOrchestrator
from src.scanners.semgrep import SemgrepScanner, _filter_benign_stderr


@pytest.fixture
def sample_semgrep_output() -> dict:
    """Sample Semgrep JSON output for testing."""
    return {
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli.string-concat-query",
                "path": "app/routes/users.py",
                "start": {"line": 42, "col": 5},
                "end": {"line": 42, "col": 60},
                "extra": {
                    "severity": "ERROR",
                    "message": "Possible SQL injection via string concatenation in query",
                    "lines": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                    "metadata": {
                        "cwe": ["CWE-89"],
                        "owasp": ["A1:2017-Injection"],
                    },
                },
            },
            {
                "check_id": "python.flask.security.xss.template-injection",
                "path": "app/utils/render.py",
                "start": {"line": 15, "col": 1},
                "end": {"line": 15, "col": 45},
                "extra": {
                    "severity": "WARNING",
                    "message": "Unescaped user input in render_template_string",
                    "lines": "return render_template_string(user_input)",
                    "metadata": {
                        "cwe": ["CWE-79"],
                    },
                },
            },
            {
                "check_id": "python.lang.security.hardcoded-password",
                "path": "config/settings.py",
                "start": {"line": 8, "col": 1},
                "end": {"line": 8, "col": 30},
                "extra": {
                    "severity": "INFO",
                    "message": "Hardcoded password detected",
                    "lines": 'DB_PASSWORD = "admin123"',
                    "metadata": {},
                },
            },
        ],
        "errors": [],
    }


class TestSemgrepScanner:
    """Tests for the SemgrepScanner class."""

    def test_filter_benign_stderr(self):
        """Requests dependency warnings should be filtered, not logged."""
        stderr = (
            "C:\\path\\site-packages\\requests\\__init__.py:113: "
            "RequestsDependencyWarning: urllib3 mismatch\n"
            "real semgrep error: something else"
        )

        filtered = _filter_benign_stderr(stderr)

        assert "RequestsDependencyWarning" not in filtered
        assert "real semgrep error" in filtered

    def test_filter_benign_stderr_with_full_dependency_warning(self):
        """The full requests dependency warning should be removed entirely."""
        stderr = (
            "C:\\Users\\Dhruv\\AppData\\Local\\Programs\\Python\\Python312\\Lib\\site-packages\\requests\\__init__.py:113: "
            "RequestsDependencyWarning: urllib3 (2.6.3) or chardet (7.2.0)/charset_normalizer (3.4.6) doesn't match a supported version!\n"
        )

        filtered = _filter_benign_stderr(stderr)

        assert filtered == ""

    def test_parse_output(self, sample_semgrep_output):
        """Verify Semgrep JSON output is correctly parsed into RawFindings."""
        scanner = SemgrepScanner()
        stdout = json.dumps(sample_semgrep_output)
        findings = scanner._parse_output(stdout)

        assert len(findings) == 3

        # Check first finding (SQL Injection)
        sqli = findings[0]
        assert sqli.tool_source == "semgrep"
        assert sqli.file == "app/routes/users.py"
        assert sqli.line_start == 42
        assert sqli.severity == "ERROR"
        assert sqli.vuln_type == "SQL_INJECTION"
        assert sqli.cwe_id == "CWE-89"
        assert sqli.confidence == 0.9  # ERROR → 0.9

        # Check second finding (XSS)
        xss = findings[1]
        assert xss.vuln_type == "XSS"
        assert xss.severity == "WARNING"
        assert xss.confidence == 0.7

    def test_parse_empty_output(self):
        """Empty output should return empty list."""
        scanner = SemgrepScanner()
        findings = scanner._parse_output("")
        assert findings == []

    def test_parse_invalid_json(self):
        """Invalid JSON should return empty list, not crash."""
        scanner = SemgrepScanner()
        findings = scanner._parse_output("not valid json{{{")
        assert findings == []

    def test_parse_no_results(self):
        """JSON with no results should return empty list."""
        scanner = SemgrepScanner()
        findings = scanner._parse_output('{"results": [], "errors": []}')
        assert findings == []

    @patch("src.scanners.semgrep.subprocess.run")
    @patch("src.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
    def test_run_success(self, mock_which, mock_run, sample_semgrep_output, tmp_path):
        """Successful scan should return parsed findings."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(sample_semgrep_output),
            stderr="",
        )

        scanner = SemgrepScanner()
        findings = scanner.run(str(tmp_path))

        assert len(findings) == 3
        mock_run.assert_called_once()

    @patch("src.scanners.semgrep.subprocess.run")
    @patch("src.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
    def test_run_timeout(self, mock_which, mock_run, tmp_path):
        """Timeout should raise ScannerError."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=120)

        scanner = SemgrepScanner(config=SemgrepConfig(timeout=120))
        with pytest.raises(ScannerError, match="timed out"):
            scanner.run(str(tmp_path))

    def test_run_nonexistent_path(self):
        """Scanning a nonexistent path should raise ScannerError."""
        scanner = SemgrepScanner()
        with pytest.raises(ScannerError, match="does not exist"):
            scanner.run("/nonexistent/path/that/does/not/exist")

    def test_build_command(self):
        """Verify CLI command construction."""
        config = SemgrepConfig(config="p/python", extra_args=["--exclude", "tests"])
        scanner = SemgrepScanner(config=config)
        cmd = scanner._build_command("/my/project")

        assert "semgrep" in cmd
        assert "--json" in cmd
        assert "--config" in cmd
        assert "p/python" in cmd
        assert "--exclude" in cmd
        assert "tests" in cmd


def test_url_scan_failure_returns_incomplete_finding():
    """A failed target must never be reported as a clean scan."""
    from src.models.schemas import ScanConfig

    orchestrator = ScannerOrchestrator(ScanConfig(scanners_enabled=["url-scanner"]))
    error = ScannerError("url-scanner", "Cannot reach target: timed out")
    with patch.object(orchestrator._url_scanner, "run", side_effect=error):
        findings = orchestrator._run_url_scan("https://unreachable.example")

    assert len(findings) == 1
    assert findings[0].vuln_type == "SCAN_INCOMPLETE"
    assert findings[0].raw["scan_complete"] is False
