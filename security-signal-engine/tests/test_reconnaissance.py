from src.scanners.reconnaissance import build_recon_findings, collect_surface


class Response:
    status_code = 200
    text = (
        "<title>Demo</title><a href='/api/users'>Users</a>"
        "<script src='/static/app.js'></script>"
        "<form method='post' action='/login'></form>"
    )
    headers = {"content-type": "text/html", "server": "Example/1.0"}


def test_reconnaissance_collects_endpoints_forms_and_technology():
    surface = collect_surface(Response(), "https://example.test/")
    finding = build_recon_findings(Response(), "https://example.test/")[0]

    assert "https://example.test/api/users" in surface["links"]
    assert surface["forms"] == [{"method": "POST", "action": "https://example.test/login"}]
    assert finding.raw["technologies"] == ["Example/1.0"]
    assert finding.vuln_type == "RECONNAISSANCE_SURFACE"