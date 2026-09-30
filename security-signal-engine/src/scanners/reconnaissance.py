"""Passive reconnaissance helpers for authorized web assessments."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from src.models.schemas import RawFinding


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict[str, str]] = []
        self._form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "a" and attributes.get("href"):
            self.links.add(attributes["href"])
        elif tag.lower() == "script" and attributes.get("src"):
            self.scripts.add(attributes["src"])
        elif tag.lower() == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "GET").upper(),
            }

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def collect_surface(response, page_url: str) -> dict[str, object]:
    """Collect bounded, non-sensitive attack-surface metadata from a page."""
    parser = _SurfaceParser()
    parser.feed(response.text[:500_000])
    return {
        "title": next(
            (part.strip() for part in response.text[:500_000].split("<title>", 1)[-1].split("</title>", 1)[:1]),
            "",
        )[:200],
        "links": sorted(urljoin(page_url, link) for link in parser.links)[:100],
        "scripts": sorted(urljoin(page_url, script) for script in parser.scripts)[:50],
        "forms": [
            {"method": form["method"], "action": urljoin(page_url, form["action"] or page_url)}
            for form in parser.forms[:50]
        ],
    }


def build_recon_findings(response, page_url: str) -> list[RawFinding]:
    """Convert passive surface metadata into a single auditable finding."""
    surface = collect_surface(response, page_url)
    server = response.headers.get("server", "")
    powered_by = response.headers.get("x-powered-by", "")
    technologies = [value for value in (server, powered_by) if value]
    body = (
        f"Title: {surface['title'] or '(none)'}\n"
        f"Status: {response.status_code}\n"
        f"Content-Type: {response.headers.get('content-type', '(none)')}\n"
        f"Technologies disclosed: {', '.join(technologies) or '(none)'}\n"
        f"Same-page links: {len(surface['links'])}\n"
        f"Forms: {len(surface['forms'])}\n"
        f"Scripts: {len(surface['scripts'])}"
    )
    return [RawFinding(
        tool_source="url-scanner",
        file=page_url,
        line_start=0,
        severity="INFO",
        vuln_type="RECONNAISSANCE_SURFACE",
        description=(
            "Passive reconnaissance inventory of the reachable page. "
            "Use the listed endpoints, forms, scripts, and disclosed technologies "
            "to prioritize authorized follow-up testing."
        ),
        rule_id="recon-page-surface",
        cwe_id="CWE-200",
        confidence=1.0,
        code_snippet=body,
        raw={"url": page_url, "surface": surface, "technologies": technologies},
    )]