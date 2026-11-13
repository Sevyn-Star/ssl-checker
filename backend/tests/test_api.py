import logging
from dataclasses import replace

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.main import app
from app.services.limiter import limiter

_FIELDS = (
    "certificate_type",
    "public_key",
    "serial_hex",
    "fingerprint_sha256",
    "alerts",
)


@pytest.fixture(autouse=True)
def _clear_limiter() -> None:
    limiter.clear()
    yield
    limiter.clear()


def _success(status: str = "valid") -> dict:
    return {
        "ok": True,
        "cached": False,
        "host": "example.com",
        "display_host": "example.com",
        "resolved_ip": "1.1.1.1",
        "checked_at": "2026-11-12T00:00:00Z",
        "elapsed_ms": 5,
        "overall": {
            "status": status,
            "label": "证书有效" if status == "valid" else "证书过期",
        },
        "validity": {
            "not_before": "2026-11-12T00:00:00Z",
            "not_after": "2027-02-09T00:00:00Z",
            "remaining_days": 80 if status == "valid" else 0,
            "risk_level": "ok" if status == "valid" else "expired",
        },
        "certificate_type": "dv",
        "certificate_type_label": "DV SSL",
        "certificate_type_source": "policy",
        "issuer": {
            "organization": "Let's Encrypt",
            "common_name": "R3",
            "distinguished_name": "CN=R3",
        },
        "subject": {
            "common_name": "example.com",
            "organization": None,
            "distinguished_name": "CN=example.com",
        },
        "domain_match": {
            "matched": True,
            "matched_name": "example.com",
            "source": "san",
            "cn": "example.com",
            "san_dns": ["example.com"],
            "san_ip": [],
            "wildcard": False,
        },
        "chain": {
            "status": "complete",
            "label": "完整",
            "openssl_error": None,
            "items": [],
        },
        "tls": {"version": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
        "public_key": {"algorithm": "ECDSA", "detail": "P-256"},
        "serial_hex": "0a1b",
        "fingerprint_sha256": "AA:BB",
        "alerts": [],
    }


@pytest.mark.anyio
async def test_check_returns_the_result_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.check.check_host", lambda raw, *, refresh=False, now=None: _success())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/check", json={"host": "example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["tls"]["version"] == "TLS 1.3"
    for name in _FIELDS:
        assert name in body
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.anyio
async def test_expired_result_is_http_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.api.check.check_host",
        lambda raw, *, refresh=False, now=None: _success("expired"),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/check", json={"host": "example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["overall"]["status"] == "expired"


@pytest.mark.anyio
async def test_invalid_host_is_400_before_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("网络不该执行")

    monkeypatch.setattr("app.services.checker.fetch_peer", explode)
    monkeypatch.setattr("app.services.checker.resolve_public_ips", explode)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/check", json={"host": "example.com;id"})
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["host"] == "example.com;id"
    assert body["error"]["code"] == "invalid_host"
    assert body["error"]["message"] == "请输入域名，例如 example.com。"


@pytest.mark.anyio
async def test_missing_or_broken_json_is_invalid_host() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.post("/api/v1/check", json={"refresh": False})
        broken = await client.post(
            "/api/v1/check",
            content=b"not-json",
            headers={"content-type": "application/json"},
        )
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "invalid_host"
    assert missing.json()["host"] == ""
    assert broken.status_code == 400
    assert broken.json()["error"]["code"] == "invalid_host"


@pytest.mark.anyio
async def test_third_request_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.api.check.settings",
        replace(settings, rate_limit_per_minute=2),
    )
    monkeypatch.setattr("app.api.check.check_host", lambda raw, *, refresh=False, now=None: _success())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = []
        last = None
        for _ in range(3):
            last = await client.post("/api/v1/check", json={"host": "example.com"})
            statuses.append(last.status_code)
    assert statuses == [200, 200, 429]
    assert last is not None
    assert last.json()["error"] == {
        "code": "rate_limited",
        "message": "检测过于频繁，请稍后再试。",
    }


@pytest.mark.anyio
async def test_log_line_does_not_include_the_certificate(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

    def fake(raw: str, *, refresh: bool = False, now: object = None) -> dict:
        body = _success()
        body["fingerprint_sha256"] = pem
        body["issuer"]["distinguished_name"] = pem
        return body

    monkeypatch.setattr("app.api.check.check_host", fake)
    caplog.set_level(logging.INFO, logger="app.api.check")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/check", json={"host": "example.com"})
    assert response.status_code == 200
    assert "BEGIN CERTIFICATE" not in caplog.text
    assert "host=example.com" in caplog.text
    assert "status=valid" in caplog.text
    assert "chain=complete" in caplog.text


@pytest.mark.anyio
async def test_forwarded_for_is_used_only_when_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.check.check_host", lambda raw, *, refresh=False, now=None: _success())
    monkeypatch.setattr(
        "app.api.check.settings",
        replace(settings, rate_limit_per_minute=1, trust_proxy=False),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/api/v1/check",
            json={"host": "example.com"},
            headers={"X-Forwarded-For": "198.51.100.8"},
        )
        second = await client.post(
            "/api/v1/check",
            json={"host": "example.com"},
            headers={"X-Forwarded-For": "198.51.100.9"},
        )
    assert first.status_code == 200
    assert second.status_code == 429

    limiter.clear()
    monkeypatch.setattr(
        "app.api.check.settings",
        replace(settings, rate_limit_per_minute=1, trust_proxy=True),
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        left = await client.post(
            "/api/v1/check",
            json={"host": "example.com"},
            headers={"X-Forwarded-For": "  198.51.100.8, 10.0.0.1"},
        )
        same = await client.post(
            "/api/v1/check",
            json={"host": "example.com"},
            headers={"X-Forwarded-For": "198.51.100.8, 10.9.9.9"},
        )
        other = await client.post(
            "/api/v1/check",
            json={"host": "example.com"},
            headers={"X-Forwarded-For": "198.51.100.9"},
        )
    assert left.status_code == 200
    assert same.status_code == 429
    assert other.status_code == 200
