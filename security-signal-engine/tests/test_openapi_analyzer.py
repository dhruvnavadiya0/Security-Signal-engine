from src.scanners.openapi_analyzer import analyze_openapi_document, parse_openapi


def test_openapi_flags_unsecured_state_changing_operations():
    findings = analyze_openapi_document({
        "openapi": "3.0.0",
        "info": {"title": "Example", "version": "1"},
        "paths": {
            "/users": {"post": {"responses": {"200": {}}}},
            "/health": {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {}}}},
        },
    }, "https://example.test/openapi.json")

    assert {finding.vuln_type for finding in findings} == {"API_MISSING_AUTH", "API_SECURITY_MISCONFIGURATION"}
    assert findings[0].raw["spec_url"] == "https://example.test/openapi.json"


def test_openapi_parser_accepts_yaml_and_rejects_non_specs():
    document = parse_openapi("openapi: 3.0.0\npaths: {}\n", "application/yaml")

    assert document["openapi"] == "3.0.0"
    assert parse_openapi("title: ordinary document\n", "application/yaml") is None