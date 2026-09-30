"""
CLI entry point for the Security Signal Engine.

Usage:
    sse scan --path ./my-project
    sse scan --path ./my-project --output json
    sse scan --path ./my-project --fail-on critical --quiet
    sse server
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Force UTF-8 encoding for stdout on Windows to support emojis
if sys.stdout and hasattr(sys.stdout, 'encoding') and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.config import load_config
from src.llm.client import OllamaClient
from src.models.schemas import ScanConfig
from src.pipeline import ScanPipeline
from src.reports.cli_report import print_cli_report
from src.reports.json_report import generate_json_report, save_json_report
from src.reports.sarif_report import generate_sarif_report, save_sarif_report
from src.runtime.sandbox import DockerSandbox, SandboxConfig, SandboxError

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


class SanitizedPath(click.ParamType):
    """Custom path parameter type that strips accidental trailing quote characters from Windows shell escaping."""
    name = "sanitized_path"

    def __init__(self, exists: bool = False, file_okay: bool = True, dir_okay: bool = True):
        self.exists = exists
        self.file_okay = file_okay
        self.dir_okay = dir_okay

    def convert(self, value, param, ctx):
        if value is None:
            return None
        if isinstance(value, Path):
            cleaned = str(value)
        else:
            cleaned = str(value).strip().strip('"').strip("'")
        p = Path(cleaned)
        if self.exists and not p.exists():
            self.fail(f"Path '{cleaned}' does not exist.", param, ctx)
        return str(p)


@click.group()
@click.version_option(version="1.0.0", prog_name="Security Signal Engine")
def main():
    """🛡️  Security Signal Engine — Intelligent Cybersecurity Analysis."""
    pass


@main.command()
@click.option("--target", "targets", multiple=True, help="Target URL, directory, or API specification. Repeatable.")
@click.option("--target-list", type=SanitizedPath(exists=True, dir_okay=False), help="File containing one target per line.")
@click.option(
    "--path",
    required=False,
    type=SanitizedPath(exists=True),
    default=None,
    help="Path to the project directory to scan.",
)
@click.option(
    "--url",
    required=False,
    type=str,
    default=None,
    help="URL of the website to scan (e.g. https://example.com).",
)
@click.option(
    "--output",
    type=click.Choice(["cli", "json", "sarif"], case_sensitive=False),
    default="cli",
    help="Output format (default: cli). SARIF is suitable for CI code scanning.",
)
@click.option(
    "--output-file",
    type=click.Path(),
    default=None,
    help="Path to save JSON or SARIF output.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Fail with exit code 1 if findings of this severity or higher are found.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to YAML configuration file.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress output (for CI/CD). Only print errors and set exit code.",
)
@click.option(
    "--no-llm",
    is_flag=True,
    default=False,
    help="Disable LLM enrichment (use rule-based fallback only).",
)
@click.option("--scan-mode", type=click.Choice(["quick", "standard", "deep"], case_sensitive=False), default="standard", show_default=True)
@click.option("--scope-mode", type=click.Choice(["auto", "diff", "full"], case_sensitive=False), default="auto", show_default=True)
@click.option("--diff-base", default=None, help="Git ref used by diff scope mode.")
@click.option("--instruction", default=None, help="Additional analyst instructions.")
@click.option("--instruction-file", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--max-budget", type=float, default=None, help="Maximum analysis budget in USD.")
@click.option("--max-turns", type=int, default=20, show_default=True)
@click.option("--pentest-model", default=None, help="Ollama model for website pentest analysis.")
@click.option("--non-interactive", is_flag=True, default=False, help="Run without interactive prompts.")
@click.option(
    "--profile",
    type=click.Choice(["precision", "balanced", "recall", "default"], case_sensitive=False),
    default=None,
    help="Preset tuning profile (e.g. precision, balanced, recall).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
def scan(path, url, output, output_file, fail_on, config_path, quiet, no_llm, verbose,
         targets, target_list, scan_mode, scope_mode, diff_base, instruction,
         instruction_file, max_budget, max_turns, pentest_model, non_interactive, profile):
    """Run a security scan on a local project directory or a website URL."""
    # Validate that exactly one of --path or --url is provided
    requested_targets = list(targets)
    if target_list:
        requested_targets.extend(
            line.strip() for line in Path(target_list).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    if path:
        requested_targets.append(path)
    if url:
        requested_targets.append(url)

    if len(requested_targets) == 0:
        console.print("  [bold red]Error:[/] Provide either --path or --url.")
        console.print("  Example: sse scan --path ./my-project")
        console.print("  Example: sse scan --url https://example.com")
        sys.exit(2)
    if instruction_file:
        instruction = Path(instruction_file).read_text(encoding="utf-8")

    # Configure logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        # Keep third-party transport logs quiet; they can flood output during URL scans.
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    # Load config
    settings = load_config(config_path, profile=profile)

    # Build scan config with CLI overrides
    scan_config = ScanConfig(
        scanners_enabled=settings.scanners_enabled,
        semgrep=settings.semgrep,
        llm=settings.llm,
        scoring=settings.scoring,
        fail_on=fail_on,
        output_format=output,
        # New subsystem configs
        rate_limiter=settings.rate_limiter,
        crawler=settings.crawler,
        traffic_store=settings.traffic_store,
        oast=settings.oast,
        fp_filter=settings.fp_filter,
        plugins=settings.plugins,
        scan_mode=scan_mode,
        scope_mode=scope_mode,
        max_budget=max_budget,
        max_turns=max_turns,
        instruction=instruction or "",
        pentest_model=pentest_model or settings.pentest_model,
    )

    if no_llm:
        scan_config.llm.enabled = False

    # Resolve target. Multi-target execution is deliberately sequential so
    # request and model budgets remain predictable.
    if len(requested_targets) > 1:
        console.print("  [yellow]Multiple targets are currently scanned sequentially; use JSON/SARIF per target for separate artifacts.[/]")
    requested_target = requested_targets[0]
    if requested_target.startswith(("http://", "https://")):
        # Ensure the URL has a scheme
        target = requested_target
        target_display = target
        target_icon = "🌐"
    else:
        target = str(Path(requested_target).resolve())
        target_display = target
        target_icon = "📂"

    if target.startswith(("http://", "https://")):
        scan_config.llm.model = scan_config.pentest_model

    if not quiet:
        console.print()
        console.print("  🛡️  [bold cyan]Security Signal Engine[/] v1.0.0")
        console.print(f"  {target_icon} Target: [cyan]{target_display}[/]")
        if requested_target.startswith(("http://", "https://")):
            console.print("  🔍 Mode: [bold]Website Security Scan[/]")
        console.print()

    # Run pipeline with progress spinner
    pipeline = ScanPipeline(config=scan_config)

    if quiet:
        report = pipeline.run(target)
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Starting scan...", total=None)

            def on_progress(stage: str, status: str = "running"):
                if status == "running":
                    progress.update(task, description=f"{stage}...")
                else:
                    progress.update(task, description=f"{stage} ✓")

            report = pipeline.run(target, progress_callback=on_progress)

    # Output report
    if output == "json":
        if output_file:
            save_json_report(report, output_file)
            if not quiet:
                console.print(f"  📄 Report saved to: [cyan]{output_file}[/]")
        else:
            click.echo(generate_json_report(report))
    elif output == "sarif":
        if output_file:
            save_sarif_report(report, output_file)
            if not quiet:
                console.print(f"  📄 SARIF report saved to: [cyan]{output_file}[/]")
        else:
            click.echo(generate_sarif_report(report))
    elif not quiet:
        print_cli_report(report)

    # Check fail-on threshold
    if pipeline.should_fail(report):
        if not quiet:
            console.print(
                f"\n  [bold red]❌ FAILED:[/] Findings at or above "
                f"[bold]{fail_on.upper()}[/] severity detected.\n",
            )
        sys.exit(1)
    else:
        sys.exit(0)


@main.command()
def doctor():
    """Check local Ollama and optional Docker sandbox readiness."""
    settings = load_config()
    ollama = OllamaClient(settings.llm)
    console.print(f"  Ollama: {'ready' if ollama.is_available() else 'unavailable'}")
    sandbox = DockerSandbox(SandboxConfig(
        image=settings.sandbox.image,
        network=settings.sandbox.network,
        memory=settings.sandbox.memory,
        cpus=settings.sandbox.cpus,
        timeout_seconds=settings.sandbox.timeout_seconds,
    ))
    try:
        sandbox.check_available()
        console.print("  Docker: ready")
    except SandboxError as error:
        console.print(f"  Docker: unavailable ({error})")


@main.command()
@click.option("--host", default="0.0.0.0", help="API host (default: 0.0.0.0)")
@click.option("--port", default=8000, type=int, help="API port (default: 8000)")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload")
def server(host, port, reload):
    """Start the FastAPI server."""
    import uvicorn
    console.print(f"  🚀 Starting API server at [cyan]http://{host}:{port}[/]")
    console.print(f"  📖 Docs available at [cyan]http://{host}:{port}/docs[/]")
    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@main.command()
@click.option("--ground-truth", required=True, type=SanitizedPath(exists=True, dir_okay=False), help="Path to ground_truth.json")
@click.option("--target", required=True, type=SanitizedPath(exists=True), help="Path to benchmark testcode directory")
@click.option("--output-dir", type=click.Path(), default="benchmarks/runs/tuning", help="Output directory for tuning artifacts")
@click.option("--profile", default="balanced", type=click.Choice(["default", "precision", "balanced", "recall"], case_sensitive=False), help="Tuning profile preset to evaluate")
def tune(ground_truth, target, output_dir, profile):
    """Run automated benchmark tuning and threshold calibration."""
    from src.evaluation.tuning import run_benchmark_tuning
    console.print(f"  ⚡ Running automated benchmark tuning with profile [bold cyan]{profile}[/]...")
    summary = run_benchmark_tuning(
        ground_truth_path=Path(ground_truth),
        target_path=Path(target),
        output_dir=Path(output_dir),
        profile_name=profile,
    )
    console.print("  [bold green]✓ Tuning complete![/]")
    console.print(f"    • Precision: [bold]{summary['precision']:.4f}[/]")
    console.print(f"    • Recall:    [bold]{summary['recall']:.4f}[/]")
    console.print(f"    • F1 Score:  [bold]{summary['f1_score']:.4f}[/]")
    console.print(f"    • PR-AUC:    [bold]{summary['pr_auc']:.4f}[/]")
    console.print(f"    • True Positives:  [green]{summary['true_positives']}[/]")
    console.print(f"    • False Positives: [red]{summary['false_positives']}[/]")
    console.print(f"    • False Negatives: [yellow]{summary['false_negatives']}[/]")


if __name__ == "__main__":
    main()
