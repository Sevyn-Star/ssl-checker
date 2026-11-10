import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.anyio
async def test_health_ok() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["openssl"].startswith("OpenSSL 3")
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.anyio
async def test_health_runtime_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> str:
        raise RuntimeError("openssl missing")

    monkeypatch.setattr("app.api.health.ensure_runtime", boom)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
    assert response.status_code == 503
    assert response.json() == {"ok": False, "openssl": ""}
