"""Tests for automated fine-tuning, threshold optimization, and profile presets."""

from pathlib import Path
import pytest
from src.config import load_config
from src.evaluation.tuning import compute_optimal_cutoffs, generate_tuned_profile
from src.pipeline import ScanPipeline


def test_tuning_optimal_cutoffs():
    sweep_curve = [
        {"threshold": 0.1, "precision": 0.5, "recall": 0.9, "f1": 0.6429, "total_predicted": 10},
        {"threshold": 0.5, "precision": 0.85, "recall": 0.8, "f1": 0.8242, "total_predicted": 8},
        {"threshold": 0.9, "precision": 1.0, "recall": 0.4, "f1": 0.5714, "total_predicted": 4},
    ]
    operating_points = compute_optimal_cutoffs(sweep_curve, min_precision=0.80, min_recall=0.70)
    assert operating_points["max_f1"]["threshold"] == 0.5
    assert operating_points["max_f1"]["f1"] == 0.8242
    assert operating_points["precision_priority"]["threshold"] == 0.5
    assert operating_points["recall_priority"]["threshold"] == 0.5


def test_generate_tuned_profile():
    rule_ranking = [
        {"rule_id": "rule_a", "precision": 0.95, "true_positive": 10, "false_positive": 0},
        {"rule_id": "rule_b", "precision": 0.40, "true_positive": 5, "false_positive": 10},
    ]
    operating_points = {
        "max_f1": {"threshold": 0.5},
        "precision_priority": {"threshold": 0.8},
        "recall_priority": {"threshold": 0.3},
    }
    precision_profile = generate_tuned_profile(rule_ranking, operating_points, "precision")
    assert precision_profile["semgrep"]["rule_allowlist"] == ["rule_a"]
    assert precision_profile["scoring"]["high_threshold"] >= 0.80

    balanced_profile = generate_tuned_profile(rule_ranking, operating_points, "balanced", min_rule_precision=0.80)
    assert "rule_a" in balanced_profile["semgrep"]["rule_allowlist"]


def test_load_config_profiles():
    precision_settings = load_config(profile="precision")
    assert precision_settings.llm.enabled is False
    assert len(precision_settings.semgrep.rule_allowlist) > 0

    balanced_settings = load_config(profile="balanced")
    assert balanced_settings.fp_filter.enabled is True

    recall_settings = load_config(profile="recall")
    assert "url-scanner" in recall_settings.scanners_enabled
