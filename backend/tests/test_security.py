import socket
from pathlib import Path

import pytest

import app.security as security
from app.security import (
    HostRejected,
    NormalizedHost,
    ResolveFailed,
    is_public_ip,
    normalize_host,
    resolve_public_ips,
)

_MESSAGES = {
    "invalid_host": "请输入域名，例如 example.com。",
    "port_not_allowed": "目前只检测 443 端口。",
    "blocked_host": "这个地址不能检测。",
    "dns_failed": "无法解析这个域名。",
    "no_public_ip": "这个域名没有可用的公网地址。",
}
_FORBIDDEN_IN_BLOCKED = ("内网", "回环", "169.254")


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        ("  Example.COM.  ", "example.com"),
        ("https://Example.COM/a?b=1", "example.com"),
        ("example.com:443", "example.com"),
        ("example.com/a?b=1", "example.com"),
    ],
)
def test_normalize_accepts_domain(raw: str, host: str) -> None:
    assert normalize_host(raw) == NormalizedHost(host, host, False)


def test_normalize_accepts_public_ipv4() -> None:
    assert normalize_host("8.8.8.8") == NormalizedHost("8.8.8.8", "8.8.8.8", True)


def test_normalize_accepts_bracketed_public_ipv6() -> None:
    got = normalize_host("[2606:4700:4700::1111]")
    assert got == NormalizedHost("2606:4700:4700::1111", "2606:4700:4700::1111", True)
    assert normalize_host("[2606:4700:4700::1111]:443") == got


def test_normalize_idna_keeps_unicode_display() -> None:
    got = normalize_host("例子.测试")
    assert got.host == "xn--fsqu00a.xn--0zwm56d"
    assert got.host.startswith("xn--")
    assert got.display_host == "例子.测试"
    assert got.is_ip is False


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("example.com:8443", "port_not_allowed"),
        ("https://user:pass@example.com", "invalid_host"),
        ("example.com;id", "invalid_host"),
        ("example.com\nid", "invalid_host"),
        ("-servername", "invalid_host"),
        ("*.example.com", "invalid_host"),
        ("com", "invalid_host"),
        ("", "invalid_host"),
        ("   ", "invalid_host"),
        ("localhost", "blocked_host"),
        ("printer.local", "blocked_host"),
        ("foo.localhost", "blocked_host"),
        ("foo.internal", "blocked_host"),
        ("127.0.0.1", "blocked_host"),
        ("10.1.2.3", "blocked_host"),
        ("169.254.169.254", "blocked_host"),
        ("100.64.0.1", "blocked_host"),
        ("192.0.2.1", "blocked_host"),
        ("198.51.100.1", "blocked_host"),
        ("203.0.113.1", "blocked_host"),
        ("224.0.0.1", "blocked_host"),
        ("[::1]", "blocked_host"),
        ("[fe80::1]", "blocked_host"),
        ("[fc00::1]", "blocked_host"),
        ("[fec0::1]", "blocked_host"),
        ("[2001:db8::1]", "blocked_host"),
    ],
)
def test_normalize_rejects(raw: str, code: str) -> None:
    with pytest.raises(HostRejected) as caught:
        normalize_host(raw)
    err = caught.value
    assert err.code == code
    assert err.message == _MESSAGES[code]
    assert str(err) == _MESSAGES[code]
    if code == "blocked_host":
        for word in _FORBIDDEN_IN_BLOCKED:
            assert word not in err.message


def test_normalize_rejects_non_string() -> None:
    with pytest.raises(HostRejected) as caught:
        normalize_host(None)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_host"
    assert caught.value.message == _MESSAGES["invalid_host"]


def test_label_and_total_length() -> None:
    long_ok = ".".join(["a" * 63, "a" * 63, "a" * 63, "b" * 61])
    assert len(long_ok) == 253
    assert normalize_host(long_ok).host == long_ok

    too_long = ".".join(["a" * 63, "a" * 63, "a" * 63, "b" * 62])
    assert len(too_long) == 254
    with pytest.raises(HostRejected) as caught:
        normalize_host(too_long)
    assert caught.value.code == "invalid_host"

    with pytest.raises(HostRejected) as caught:
        normalize_host("a" * 64 + ".com")
    assert caught.value.code == "invalid_host"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.1.1",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00::1",
        "ff02::1",
        "fec0::1",
        "2001:db8::1",
        "::ffff:10.1.2.3",
        "::ffff:169.254.169.254",
        "not-an-ip",
    ],
)
def test_is_public_ip_rejects_non_public(ip: str) -> None:
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_is_public_ip_accepts_public(ip: str) -> None:
    assert is_public_ip(ip) is True


def _install_dns(
    monkeypatch: pytest.MonkeyPatch,
    results: list[str],
    *,
    fail: str | None = None,
) -> None:
    def fake(
        host: str,
        port: int = 0,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host == "example.com"
        assert port == 443
        assert type == socket.SOCK_STREAM
        if fail == "gaierror":
            raise socket.gaierror(1, "dns failed")
        if fail == "boom":
            raise RuntimeError("boom")
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port)) for ip in results]

    monkeypatch.setattr(security.socket, "getaddrinfo", fake)


def test_resolve_drops_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dns(monkeypatch, ["127.0.0.1"])
    with pytest.raises(ResolveFailed) as caught:
        resolve_public_ips(normalize_host("example.com"))
    assert caught.value.code == "no_public_ip"
    assert caught.value.message == _MESSAGES["no_public_ip"]


def test_resolve_filters_private(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dns(monkeypatch, ["10.0.0.1", "1.1.1.1"])
    assert resolve_public_ips(normalize_host("example.com")) == ["1.1.1.1"]


def test_resolve_puts_ipv4_first(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dns(monkeypatch, ["2606:4700:4700::1111", "8.8.8.8", "1.1.1.1"])
    assert resolve_public_ips(normalize_host("example.com")) == [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ]


def test_resolve_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dns(monkeypatch, ["1.1.1.1", "1.1.1.1"])
    assert resolve_public_ips(normalize_host("example.com")) == ["1.1.1.1"]


def test_resolve_dns_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dns(monkeypatch, [], fail="gaierror")
    with pytest.raises(ResolveFailed) as caught:
        resolve_public_ips(normalize_host("example.com"))
    assert caught.value.code == "dns_failed"
    assert caught.value.message == _MESSAGES["dns_failed"]


def test_resolve_does_not_mask_unexpected_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dns(monkeypatch, [], fail="boom")
    with pytest.raises(RuntimeError, match="boom"):
        resolve_public_ips(normalize_host("example.com"))


def test_resolve_ip_literal_skips_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(*args: object, **kwargs: object) -> list[object]:
        raise AssertionError("IP 字面量不应再解析")

    monkeypatch.setattr(security.socket, "getaddrinfo", fake)
    assert resolve_public_ips(normalize_host("8.8.8.8")) == ["8.8.8.8"]


def test_security_source_does_not_call_subprocess() -> None:
    source = Path(security.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "subprocess" not in dir(security)
