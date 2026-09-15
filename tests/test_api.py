"""
Sentinel AI
API Tests
"""

from fastapi.testclient import TestClient

from main import app


def test_root_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Sentinel AI" in response.text


def test_api_root_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/api")

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "Sentinel AI"
    assert data["status"] == "operational"


def test_health_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"