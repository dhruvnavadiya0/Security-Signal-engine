"""Tests for importing the public OWASP benchmark labels."""

from src.evaluation.owasp import load_owasp_csv, summarize_ground_truth


def test_load_owasp_expected_results(tmp_path):
    source = tmp_path / "expectedresults.csv"
    source.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n",
        encoding="utf-8",
    )

    ground_truth = load_owasp_csv(source)
    summary = summarize_ground_truth(ground_truth)

    assert summary == {
        "cases": 2,
        "vulnerable_cases": 1,
        "clean_cases": 1,
        "vulnerability_rate": 0.5,
        "categories": {"sqli": 2},
    }
    assert ground_truth["cases"][0]["vulnerabilities"][0]["cwe_id"] == "CWE-89"
    assert ground_truth["cases"][1]["vulnerabilities"] == []
