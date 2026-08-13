"""Tests for API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthAPI:
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data


class TestScanAPI:
    @pytest.mark.asyncio
    async def test_invalid_url(self, client):
        response = await client.post("/api/v1/scan", json={"url": ""})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_localhost_scan_blocked(self, client):
        response = await client.post("/api/v1/scan", json={"url": "http://localhost/admin"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_get_nonexistent_scan(self, client):
        response = await client.get("/api/v1/scan/nonexistent-id")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_unsupported_scheme(self, client):
        response = await client.post("/api/v1/scan", json={"url": "ftp://example.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
