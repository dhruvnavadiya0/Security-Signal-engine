"""
Application configuration using Pydantic Settings.

Supports environment variables and YAML config file loading.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings

from src.models.schemas import (
    LLMConfig, RiskPolicyConfig, SemgrepConfig, URLScannerConfig,
    RateLimiterConfig, CrawlerConfig, TrafficStoreConfig,
    OASTConfig, FalsePositiveFilterConfig, PluginConfig,
    SandboxConfig,
)


class AppSettings(BaseSettings):
    """
    Application-wide settings.
    
    Values can be set via:
    1. Environment variables (prefixed with SSE_)
    2. YAML config file
    3. Defaults defined here
    """

    # Scanner settings
    scanners_enabled: list[str] = Field(default_factory=lambda: ["semgrep"])
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    url_scanner: URLScannerConfig = Field(default_factory=URLScannerConfig)

    # LLM settings
    llm: LLMConfig = Field(default_factory=LLMConfig)
    pentest_model: str = "xploiter/pentester:latest"

    # Scoring settings
    scoring: RiskPolicyConfig = Field(default_factory=RiskPolicyConfig)

    # New subsystem settings (competitive feature parity)
    rate_limiter: RateLimiterConfig = Field(default_factory=RateLimiterConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    traffic_store: TrafficStoreConfig = Field(default_factory=TrafficStoreConfig)
    oast: OASTConfig = Field(default_factory=OASTConfig)
    fp_filter: FalsePositiveFilterConfig = Field(default_factory=FalsePositiveFilterConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    # Output settings
    output_format: str = "cli"
    fail_on: Optional[str] = None

    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Logging
    log_level: str = "INFO"

    model_config = {
        "env_prefix": "SSE_",
        "env_nested_delimiter": "__",
        "extra": "ignore",
    }


def load_config(
    config_path: Optional[str] = None,
    profile: Optional[str] = None,
) -> AppSettings:
    """
    Load configuration from YAML file and/or environment variables.
    
    Args:
        config_path: Optional path to a YAML config file.
        profile: Optional profile preset name (e.g. 'precision', 'balanced', 'recall', 'default').
        
    Returns:
        Fully resolved AppSettings instance.
    """
    config_data: dict = {}

    # Project root = parent of the src/ package directory
    _project_root = Path(__file__).resolve().parent.parent

    # Check if a profile preset was requested
    if profile:
        profile_clean = profile.strip().lower()
        if not profile_clean.endswith(".yaml") and not profile_clean.endswith(".yml"):
            profile_filename = f"{profile_clean}_profile.yaml" if profile_clean != "default" else "default_config.yaml"
        else:
            profile_filename = profile_clean

        profile_paths = [
            _project_root / "config" / profile_filename,
            Path("config") / profile_filename,
            Path(profile_filename),
        ]
        for p in profile_paths:
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f) or {}
                break

    # Try loading from YAML file if no profile was matched or if config_path was explicitly provided
    if not config_data:
        if config_path and Path(config_path).exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}
        else:
            # Check default config locations (both relative to package root and CWD)
            default_paths = [
                _project_root / "config" / "default_config.yaml",
                _project_root / "sse_config.yaml",
                Path("config/default_config.yaml"),
                Path("sse_config.yaml"),
                Path(os.path.expanduser("~/.sse/config.yaml")),
            ]
            for p in default_paths:
                if p.exists():
                    with open(p, "r", encoding="utf-8") as f:
                        config_data = yaml.safe_load(f) or {}
                    break

    # These aliases match the Strix-style provider contract while retaining
    # the existing SSE_* nested configuration names.
    env_aliases = {
        "LLM_API_KEY": ("llm", "api_key"),
        "LLM_API_BASE": ("llm", "base_url"),
        "STRIX_LLM": ("llm", "model"),
        "LLM_TIMEOUT": ("llm", "timeout"),
    }
    for env_name, (section, key) in env_aliases.items():
        value = os.getenv(env_name)
        if value is not None:
            config_data.setdefault(section, {})[key] = value

    if os.getenv("LLM_DISABLE_STREAMING") in {"1", "true", "TRUE"}:
        config_data.setdefault("llm", {})["streaming"] = False
    if os.getenv("STRIX_PENTEST_MODEL"):
        config_data["pentest_model"] = os.environ["STRIX_PENTEST_MODEL"]

    return AppSettings(**config_data)


# Singleton for easy import
_settings: Optional[AppSettings] = None


def get_settings(config_path: Optional[str] = None) -> AppSettings:
    """Get or create the global settings instance."""
    global _settings
    if _settings is None:
        _settings = load_config(config_path)
    return _settings
