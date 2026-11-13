import socket
from datetime import timedelta
from pathlib import Path

import pytest

from app.services import cache
from app.services.checker import check_host
from app.services.limiter import Limiter
from app.services.openssl_client import FetchError, PeerMaterial, VerifyRaw
from app.services.parser import parse_certificate

FIXTURES = Path(__file__).parent / "fixtures"
LEAF_PEM = (FIXTURES / "leaf_ok.pem").read_text(encoding="utf-8")
INTERMEDIATE_PEM = (FIXTURES / "intermediate.pem").read_text(encoding="utf-8")

_TOP_LEVEL = {
    "ok",
    "cached",
    "host",
    "display_host",
    "resolved_ip",
    "checked_at",
    "elapsed_ms",
    "overall",
    "validity",
    "certificate_type",
    "certificate_type_label",
    "certificate_type_source",
    "issuer",
    "subject",
    "domain_match",
    "chain",
    "tls",
    "public_key",
    "serial_hex",
    "fingerprint_sha256",
    "alerts",
}


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    cache.clear()
    yield
    cache.clear()


def _material(pems: tuple[str, ...] = (LEAF_PEM, INTERMEDIATE_PEM)) -> PeerMaterial:
    return PeerMaterial(pems, "TLS 1.3", "TLS_AES_256_GCM_SHA384")


def _patch_peer(monkeypatch: pytest.MonkeyPatch, calls: list[dict], pems: tuple[str, ...] | None = None) -> None:
    def fetch(ip: str, hostname: str | None, *, timeout: float) -> PeerMaterial:
        calls.append({"ip": ip, "hostname": hostname, "timeout": timeout})
        return _material(pems or (LEAF_PEM, INTERMEDIATE_PEM))

    def verify(leaf_pem: str, intermediate_pems: list[str], *, runner: object) -> VerifyRaw:
        return VerifyRaw("complete", None, "ISRG Root X1")

    monkeypatch.setattr("app.services.checker.fetch_peer", fetch)
    monkeypatch.setattr("app.services.checker.verify_chain", verify)
    monkeypatch.setattr("app.services.checker.resolve_public_ips", lambda host: ["1.1.1.1"])


def test_success_has_every_field(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []
    _patch_peer(monkeypatch, calls)
    leaf = parse_certificate(LEAF_PEM)
    now = leaf.not_before + timedelta(days=1)
    result = check_host("  Example.COM  ", now=now)

    assert set(result) == _TOP_LEVEL
    assert result["ok"] is True
    assert result["cached"] is False
    assert result["host"] == "example.com"
    assert result["display_host"] == "example.com"
    assert result["resolved_ip"] == "1.1.1.1"
    assert result["checked_at"].endswith("Z")
    assert isinstance(result["elapsed_ms"], int)
    assert result["domain_match"]["matched"] is True
    assert result["overall"]["status"] == "valid"
    assert result["certificate_type"] == "dv"
    assert result["certificate_type_label"] == "DV SSL"
    assert set(result["issuer"]) == {"organization", "common_name", "distinguished_name"}
    assert result["issuer"]["common_name"] == "Test Intermediate"
    assert result["public_key"] == {"algorithm": "RSA", "detail": "2048"}
    assert result["tls"]["version"] == "TLS 1.3"
    assert result["chain"]["status"] == "complete"
    assert calls[0]["hostname"] == "example.com"
    assert calls[0]["timeout"] == 10.0


def test_expired_certificate_stays_a_completed_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_peer(monkeypatch, [])
    leaf = parse_certificate(LEAF_PEM)
    result = check_host("example.com", now=leaf.not_after + timedelta(seconds=1))
    assert result["ok"] is True
    assert result["overall"]["status"] == "expired"
    assert result["chain"]["status"] == "complete"
    assert result["alerts"][0]["level"] == "expired"


def test_second_call_is_cached_until_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []
    _patch_peer(monkeypatch, calls)
    leaf = parse_certificate(LEAF_PEM)
    now = leaf.not_before + timedelta(days=1)
    first = check_host("example.com", now=now)
    second = check_host("example.com", now=now)
    assert first["cached"] is False
    assert second["cached"] is True
    assert {**second, "cached": False} == first
    assert len(calls) == 1
    check_host("example.com", refresh=True, now=now)
    assert len(calls) == 2


def test_private_resolution_never_fetches(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_dns(*_args: object, **_kwargs: object) -> list[tuple]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))]

    monkeypatch.setattr("app.security.socket.getaddrinfo", fake_dns)
    monkeypatch.setattr(
        "app.services.checker.fetch_peer",
        lambda *_args, **_kwargs: calls.append("fetch"),
    )
    result = check_host("example.com")
    assert result["ok"] is False
    assert result["error"]["code"] == "no_public_ip"
    assert result["error"]["message"] == "这个域名没有可用的公网地址。"
    assert calls == []


def test_dns_failure_is_a_result_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def boom(*_args: object, **_kwargs: object) -> list[tuple]:
        raise socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr("app.security.socket.getaddrinfo", boom)
    monkeypatch.setattr(
        "app.services.checker.fetch_peer",
        lambda *_args, **_kwargs: calls.append("fetch"),
    )
    result = check_host("example.com")
    assert result == {
        "ok": False,
        "host": "example.com",
        "error": {"code": "dns_failed", "message": "无法解析这个域名。"},
    }
    assert calls == []


def test_second_address_is_used_when_the_first_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fetch(ip: str, hostname: str | None, *, timeout: float) -> PeerMaterial:
        seen.append(ip)
        if ip == "1.1.1.1":
            raise FetchError("timeout")
        return _material()

    monkeypatch.setattr("app.services.checker.fetch_peer", fetch)
    monkeypatch.setattr(
        "app.services.checker.verify_chain",
        lambda *_args, **_kwargs: VerifyRaw("complete", None, "ISRG Root X1"),
    )
    monkeypatch.setattr(
        "app.services.checker.resolve_public_ips",
        lambda host: ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    )
    leaf = parse_certificate(LEAF_PEM)
    result = check_host("example.com", now=leaf.not_before + timedelta(days=1))
    assert seen == ["1.1.1.1", "8.8.8.8"]
    assert result["resolved_ip"] == "8.8.8.8"
    assert result["ok"] is True


def test_last_fetch_error_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    codes = ["timeout", "connect_failed"]

    def fetch(ip: str, hostname: str | None, *, timeout: float) -> PeerMaterial:
        raise FetchError(codes.pop(0))

    monkeypatch.setattr("app.services.checker.fetch_peer", fetch)
    monkeypatch.setattr("app.services.checker.resolve_public_ips", lambda host: ["1.1.1.1", "8.8.8.8"])
    result = check_host("example.com")
    assert result["error"]["code"] == "connect_failed"
    assert result["error"]["message"] == "无法连上 443 端口。"


def test_unreadable_pem_is_no_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    verify_calls: list[str] = []
    _patch_peer(monkeypatch, [], pems=("not a certificate",))
    monkeypatch.setattr(
        "app.services.checker.verify_chain",
        lambda *_args, **_kwargs: verify_calls.append("verify"),
    )
    result = check_host("example.com")
    assert result["error"]["code"] == "no_certificate"
    assert result["error"]["message"] == "服务器没有返回证书。"
    assert verify_calls == []


def test_ip_literal_does_not_send_servername(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    def fetch(ip: str, hostname: str | None, *, timeout: float) -> PeerMaterial:
        calls.append({"ip": ip, "hostname": hostname})
        return _material()

    monkeypatch.setattr("app.services.checker.fetch_peer", fetch)
    monkeypatch.setattr(
        "app.services.checker.verify_chain",
        lambda *_args, **_kwargs: VerifyRaw("complete", None, "ISRG Root X1"),
    )
    leaf = parse_certificate(LEAF_PEM)
    result = check_host("1.1.1.1", now=leaf.not_before + timedelta(days=1))
    assert calls == [{"ip": "1.1.1.1", "hostname": None}]
    assert result["resolved_ip"] == "1.1.1.1"


def test_network_failure_is_cached_until_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fetch(ip: str, hostname: str | None, *, timeout: float) -> PeerMaterial:
        calls.append(ip)
        raise FetchError("timeout")

    monkeypatch.setattr("app.services.checker.fetch_peer", fetch)
    monkeypatch.setattr("app.services.checker.resolve_public_ips", lambda host: ["1.1.1.1"])
    first = check_host("example.com")
    second = check_host("example.com")
    assert first["error"]["code"] == "timeout"
    assert second == first
    assert calls == ["1.1.1.1"]
    check_host("example.com", refresh=True)
    assert calls == ["1.1.1.1", "1.1.1.1"]


def test_cache_expires_on_injected_clock() -> None:
    cache.set("example.com", {"ok": True, "cached": False, "n": 1}, 30, now=100.0)
    hit = cache.get("example.com", now=129.0)
    assert hit is not None
    assert hit["cached"] is True
    assert cache.get("example.com", now=130.0) is None


def test_limiter_window_uses_injected_clock() -> None:
    clock = {"now": 1000.0}
    gate = Limiter(clock=lambda: clock["now"])
    assert gate.allow("203.0.113.10", 1) is True
    assert gate.allow("203.0.113.10", 1) is False
    assert gate.allow("203.0.113.11", 1) is True
    clock["now"] = 1060.0
    assert gate.allow("203.0.113.10", 1) is True
