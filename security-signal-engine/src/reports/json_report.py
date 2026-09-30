"""
JSON report generator.

Produces scan reports conforming to the JSON API response schema
defined in PRD Section 5.7.1.
"""

from __future__ import annotations

import json

from src.models.schemas import ScanReport


def generate_json_report(report: ScanReport) -> str:
    """
    Generate a formatted JSON string from a ScanReport.
    
    Args:
        report: The complete scan report.
        
    Returns:
        Pretty-printed JSON string.
    """
    return report.model_dump_json(indent=2)


def save_json_report(report: ScanReport, output_path: str) -> None:
    """
    Save the scan report as a JSON file.
    
    Args:
        report: The complete scan report.
        output_path: Path to write the JSON file.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(generate_json_report(report))
