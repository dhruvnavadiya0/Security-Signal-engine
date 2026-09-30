"""
Abstract base class for all scanner adapters.

Every scanner must implement the `run()` method which accepts a target
path and returns a list of RawFinding objects. This ensures the
orchestration engine remains agnostic to tool-specific output formats.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from src.models.schemas import RawFinding

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base class for security scanner adapters.
    
    Each adapter is responsible for:
    - Invoking the underlying tool as a subprocess
    - Parsing tool-specific output into RawFinding objects
    - Handling failures gracefully with error codes and logs
    """

    name: str = "base"

    @abstractmethod
    def run(self, target: str) -> list[RawFinding]:
        """
        Execute the scanner against the given target.
        
        Args:
            target: Path to the directory or file to scan.
            
        Returns:
            List of raw findings from the scanner.
            
        Raises:
            ScannerError: If the scanner fails to execute.
        """
        ...

    def is_available(self) -> bool:
        """Check if the scanner tool is installed and available."""
        return True


class ScannerError(Exception):
    """Raised when a scanner fails to execute."""

    def __init__(self, scanner: str, message: str, exit_code: int | None = None):
        self.scanner = scanner
        self.exit_code = exit_code
        super().__init__(f"[{scanner}] {message} (exit_code={exit_code})")
