"""Bounded OpenAPI discovery and passive API security analysis."""

from __future__ import annotations

from urllib.parse import urljoin

import yaml

from src.models.schemas import RawFinding


OPENAPI_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/docs/openapi.json",
)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def analyze_openapi_document(document: dict, spec_url: str) -> list[RawFinding]:
    """Inspect an OpenAPI document without sending state-changing requests."""
    findings: list[RawFinding] = []
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        return findings

    operations = 0
    unauthenticated = []
    state_changing = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_security = path_item.get("security")
        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            operations += 1
            security = operation.get("security", path_security)
            operation_name = f"{method.upper()} {path}"
            if security == [] or (security is None and not document.get("security")):
                unauthenticated.append(operation_name)
            if method.lower() in {"post", "put", "patch", "delete"}:
                state_changing.append(operation_name)
            if operations >= 100:
                break
        if operations >= 100:
            break

    if unauthenticated:
        sample = ", ".join(unauthenticated[:8])
        findings.append(RawFinding(
            tool_source="url-scanner",
            file=spec_url,
            line_start=0,
            severity="WARNING",
            vuln_type="API_MISSING_AUTH",
            description=(
                f"OpenAPI advertises {len(unauthenticated)} operation(s) without a security requirement. "
                "Verify these endpoints do not expose protected data or privileged actions."
            ),
            rule_id="openapi-operation-missing-security",
            cwe_id="CWE-306",
            confidence=0.75,
            code_snippet=f"Unauthenticated operations: {sample}",
            raw={"spec_url": spec_url, "operations": unauthenticated[:20]},
        ))

    if state_changing and not document.get("security"):
        findings.append(RawFinding(
            tool_source="url-scanner",
            file=spec_url,
            line_start=0,
            severity="WARNING",
            vuln_type="API_SECURITY_MISCONFIGURATION",
            description=(
                "OpenAPI defines state-changing operations but no global security scheme. "
                "Confirm authentication, authorization, CSRF protection, and rate limits "
                "are enforced server-side rather than relying on documentation."
            ),
            rule_id="openapi-no-global-security",
            cwe_id="CWE-693",
            confidence=0.70,
            code_snippet=f"State-changing operations: {', '.join(state_changing[:8])}",
            raw={"spec_url": spec_url, "operations": state_changing[:20]},
        ))

    return findings


def parse_openapi(content: str, content_type: str) -> dict | None:
    """Parse JSON or YAML OpenAPI content, returning only object documents."""
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    return document if isinstance(document, dict) and ("openapi" in document or "swagger" in document) else None


def discover_openapi(fetch, base_url: str, max_specs: int = 3) -> list[RawFinding]:
    """Try common spec locations and analyze at most a few small documents."""
    findings: list[RawFinding] = []
    checked = 0
    for path in OPENAPI_PATHS:
        if checked >= max_specs:
            break
        response = fetch(urljoin(base_url, path))
        if not response or response.status_code != 200 or len(response.content) > 2_000_000:
            continue
        document = parse_openapi(response.text, response.headers.get("content-type", ""))
        if document is None:
            continue
        checked += 1
        findings.extend(analyze_openapi_document(document, urljoin(base_url, path)))
    return findings