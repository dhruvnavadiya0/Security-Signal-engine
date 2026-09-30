"""
FastAPI application for the Security Signal Engine.

Provides REST API endpoints per PRD Section 7.5:
  POST /api/v1/scan         — Trigger full scan pipeline
  GET  /api/v1/scan/{id}    — Retrieve previous scan by ID
  GET  /api/v1/scan/{id}/report — Download PDF report
  GET  /api/v1/health       — Health check including Ollama status
  GET  /api/v1/docs         — Auto-generated OpenAPI docs (built-in)
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from src.config import get_settings
from src.llm.client import OllamaClient
from src.models.schemas import ScanConfig, ScanReport
from src.pipeline import ScanPipeline
from src.reports.pdf_report import generate_pdf_report, plan_pdf_report_path
from src.scanners.orchestrator import is_url_target

logger = logging.getLogger(__name__)

# In-memory report store (MVP — upgrade to SQLite in V1)
_report_store: dict[str, ScanReport] = {}

# ── App Setup ──────────────────────────────────────────────
app = FastAPI(
    title="Security Signal Engine",
    description=(
        "Intelligent Cybersecurity Analysis & Prioritization Platform. "
        "Aggregates, deduplicates, and risk-scores security scanner output, "
        "then enriches findings with AI-powered explanations and fix suggestions."
    ),
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ──────────────────────────────

class ScanRequest(BaseModel):
    """Request body for triggering a scan."""
    target: str = Field(..., description="Path to project directory or URL to scan")
    config: Optional[dict] = Field(default=None, description="Optional config overrides")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str = "1.0.0"
    llm_available: bool = False
    scanners_available: list[str] = []


# ── Routes ─────────────────────────────────────────────────

@app.post("/api/v1/scan", response_model=ScanReport)
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Trigger a full security scan pipeline.
    
    Accepts a target directory path or URL and optional config overrides.
    Returns a complete scan report with enriched findings.
    """
    target = request.target

    # Validate target — either URL or existing directory
    if not is_url_target(target):
        target_path = Path(target)
        if not target_path.exists():
            raise HTTPException(status_code=400, detail=f"Target path does not exist: {target}")
        if not target_path.is_dir():
            raise HTTPException(status_code=400, detail=f"Target must be a directory: {target}")
        target = str(target_path.resolve())

    # Build config
    settings = get_settings()
    scan_config = ScanConfig(
        scanners_enabled=settings.scanners_enabled,
        semgrep=settings.semgrep,
        llm=settings.llm,
    )

    # Apply any config overrides from request
    if request.config:
        for key, value in request.config.items():
            if hasattr(scan_config, key):
                setattr(scan_config, key, value)

    try:
        pipeline = ScanPipeline(config=scan_config)
        report = await asyncio.to_thread(pipeline.run, target, None, False)

        # Reserve output path and generate PDF asynchronously after response.
        report.report_path = plan_pdf_report_path(report.scan_id)

        # Store report for later retrieval
        _report_store[report.scan_id] = report

        background_tasks.add_task(_generate_scan_pdf, report.scan_id)

        return report
    except Exception as e:
        logger.error("Scan failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/api/v1/scan/{scan_id}", response_model=ScanReport)
async def get_scan(scan_id: str):
    """Retrieve a previous scan report by ID."""
    report = _report_store.get(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    return report


@app.get("/api/v1/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """
    Download the PDF report for a scan.
    
    Returns the PDF file as a download with Content-Type: application/pdf.
    """
    report = _report_store.get(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    if not report.report_path:
        raise HTTPException(
            status_code=404,
            detail="PDF report was not generated for this scan",
        )

    pdf_path = Path(report.report_path)
    if not pdf_path.exists():
        raise HTTPException(
            status_code=202,
            detail="PDF report is still being generated. Retry shortly.",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name,
    )


def _generate_scan_pdf(scan_id: str) -> None:
    """Background task for non-blocking PDF report generation."""
    report = _report_store.get(scan_id)
    if report is None:
        return

    try:
        path = generate_pdf_report(report, output_path=report.report_path)
        report.report_path = path
        _report_store[scan_id] = report
        logger.info("Background PDF generation complete for scan %s", scan_id)
    except Exception as e:
        logger.warning("Background PDF generation failed for scan %s: %s", scan_id, e)


@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns system status including LLM availability and
    which scanners are installed.
    """
    import shutil

    settings = get_settings()
    ollama = OllamaClient(settings.llm)

    scanners = []
    if shutil.which("semgrep"):
        scanners.append("semgrep")

    return HealthResponse(
        status="ok",
        version="1.0.0",
        llm_available=ollama.is_available(),
        scanners_available=scanners,
    )
