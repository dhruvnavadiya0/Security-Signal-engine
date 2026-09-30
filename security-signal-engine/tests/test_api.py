"""
Tests for the FastAPI endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from src.api.main import app


@pytest.fixture
def client():
    """Create a FastAPI test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for the /api/v1/health endpoint."""

    def test_health_returns_ok(self, client):
        """Health check should return status ok."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"
        assert "llm_available" in data
        assert "scanners_available" in data


class TestScanEndpoint:
    """Tests for the /api/v1/scan endpoint."""

    def test_scan_invalid_path(self, client):
        """Scanning a nonexistent path should return 400."""
        response = client.post(
            "/api/v1/scan",
            json={"target": "/nonexistent/path/to/project"},
        )
        assert response.status_code == 400

    def test_scan_missing_target(self, client):
        """Missing target field should return 422."""
        response = client.post("/api/v1/scan", json={})
        assert response.status_code == 422


class TestScanRetrievalEndpoint:
    """Tests for the /api/v1/scan/{scan_id} endpoint."""

    def test_get_nonexistent_scan(self, client):
        """Retrieving a nonexistent scan should return 404."""
        response = client.get("/api/v1/scan/nonexistent-id")
        assert response.status_code == 404


class TestOpenAPIDocs:
    """Tests for the OpenAPI documentation."""

    def test_openapi_docs_accessible(self, client):
        """OpenAPI docs should be accessible."""
        response = client.get("/api/v1/docs")
        assert response.status_code == 200

    def test_openapi_json_accessible(self, client):
        """OpenAPI JSON spec should be accessible."""
        response = client.get("/api/v1/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert data["info"]["title"] == "Security Signal Engine"
