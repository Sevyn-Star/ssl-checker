import os
import subprocess

import pytest

from app.services.openssl_client import (
    CommandResult,
    fetch_peer,
    run_command,
    verify_chain,
    FetchError,
)

_LEAF = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
_EXTRA = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"


def _ok(text: str) -> CommandResult:
    return CommandResult(text, "", 0, False)


def test_run_command_keeps_shell_off(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> object:
        captured["args"] = args
        captured.update(kwargs)

        class Completed:
            stdout = b"OpenSSL 3.0.0\n"
            stderr = b""
            returncode = 0

        return Completed()

    monkeypatch.setattr("app.services.openssl_client.subprocess.run", fake_run)
    result = run_command(["openssl", "version"], timeout=5)
    assert isinstance(captured["args"], list)
    assert captured["args"][0] == "openssl"
    assert captured["shell"] is False
    assert captured["input"] == b""
    assert result.timed_out is False
    assert result.stdout == "OpenSSL 3.0.0\n"


def test_run_command_turns_timeout_into_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: list[str], **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(args, kwargs["timeout"], output=b"partial", stderr=b"slow")

    monkeypatch.setattr("app.services.openssl_client.subprocess.run", fake_run)
    result = run_command(["openssl", "s_client"], timeout=1)
    assert result.timed_out is True
    assert result.stdout == "partial"
    assert result.stderr == "slow"


def test_ipv6_connect_includes_servername() -> None:
    seen: dict[str, object] = {}

    def runner(args: list[str], timeout: float) -> CommandResult:
        seen["args"] = args
        seen["timeout"] = timeout
        text = f"{_LEAF}\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n"
        return _ok(text)

    material = fetch_peer("2001:db8::1", "example.com", timeout=4, runner=runner)
    args = seen["args"]
    assert isinstance(args, list)
    assert args == [
        "openssl",
        "s_client",
        "-connect",
        "[2001:db8::1]:443",
        "-showcerts",
        "-servername",
        "example.com",
    ]
    assert seen["timeout"] == 4
    assert "-ign_eof" not in args
    assert "-brief" not in args
    assert "-verify_hostname" not in args
    assert "-verify_return_error" not in args
    assert material.pems[0] == _LEAF
    assert material.protocol == "TLS 1.3"
    assert material.cipher_suite == "TLS_AES_256_GCM_SHA384"


def test_ip_check_omits_servername() -> None:
    seen: dict[str, list[str]] = {}

    def runner(args: list[str], timeout: float) -> CommandResult:
        seen["args"] = args
        return _ok(_LEAF)

    material = fetch_peer("1.1.1.1", None, timeout=2, runner=runner)
    assert seen["args"] == ["openssl", "s_client", "-connect", "1.1.1.1:443", "-showcerts"]
    assert "-servername" not in seen["args"]
    assert material.protocol is None
    assert material.cipher_suite is None


def test_first_pem_block_is_the_leaf() -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        return _ok(f"noise\n{_LEAF}\nbetween\n{_EXTRA}\n")

    material = fetch_peer("1.1.1.1", "example.com", timeout=2, runner=runner)
    assert material.pems[0] == _LEAF
    assert material.pems[1] == _EXTRA


def test_openssl_30_session_line_supplies_protocol_and_cipher() -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        text = f"{_LEAF}\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        return _ok(text)

    material = fetch_peer("1.1.1.1", "example.com", timeout=2, runner=runner)
    assert material.protocol == "TLS 1.3"
    assert material.cipher_suite == "TLS_AES_256_GCM_SHA384"


def test_protocol_line_wins_over_session_line() -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        text = (
            f"{_LEAF}\n"
            "Protocol  : TLSv1.2\n"
            "Cipher    : ECDHE-RSA-AES128-GCM-SHA256\n"
            "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        )
        return _ok(text)

    material = fetch_peer("1.1.1.1", None, timeout=2, runner=runner)
    assert material.protocol == "TLS 1.2"
    assert material.cipher_suite == "ECDHE-RSA-AES128-GCM-SHA256"


def test_protocol_can_be_read_from_stderr() -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        return CommandResult(_LEAF, "Protocol  : TLSv1.2\nCipher    : ECDHE-RSA-AES128-GCM-SHA256\n", 0, False)

    material = fetch_peer("1.1.1.1", None, timeout=2, runner=runner)
    assert material.protocol == "TLS 1.2"
    assert material.cipher_suite == "ECDHE-RSA-AES128-GCM-SHA256"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("TLSv1.3", "TLS 1.3"),
        ("TLSv1.2", "TLS 1.2"),
        ("TLSv1.1", "TLS 1.1"),
        ("TLSv1", "TLS 1.0"),
        ("SSLv3", "SSL 3"),
        ("TLSv1.0", "TLSv1.0"),
    ],
)
def test_protocol_names(raw: str, expected: str) -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        return _ok(f"{_LEAF}\nProtocol  : {raw}\n")

    assert fetch_peer("1.1.1.1", None, timeout=1, runner=runner).protocol == expected


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (CommandResult("", "", 0, True), "timeout"),
        (CommandResult("", "connect: Connection refused", 0, False), "connect_failed"),
        (CommandResult("errno=111", "", 1, False), "connect_failed"),
        (CommandResult("errno=61", "", 1, False), "connect_failed"),
        (CommandResult("no peer certificate", "", 0, False), "no_certificate"),
        (CommandResult("", "", 0, False), "handshake_failed"),
    ],
)
def test_missing_certificate_is_classified(result: CommandResult, code: str) -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        return result

    with pytest.raises(FetchError) as caught:
        fetch_peer("1.1.1.1", "example.com", timeout=1, runner=runner)
    assert caught.value.code == code


def test_verify_success_reads_spaced_cn() -> None:
    text = "depth=2 CN = ISRG Root X1\ndepth=0 CN = example.com\n/tmp/leaf.pem: OK\n"

    def runner(args: list[str], timeout: float) -> CommandResult:
        assert isinstance(args, list)
        assert args[0] == "openssl"
        assert "-untrusted" not in args
        assert args[-1].endswith(f"{os.sep}leaf.pem")
        return _ok(text)

    raw = verify_chain(_LEAF, [], runner=runner)
    assert raw.status == "complete"
    assert raw.openssl_error is None
    assert raw.root_common_name == "ISRG Root X1"


def test_verify_error_20_is_incomplete() -> None:
    text = "depth=0 CN=example.com\nerror 20 at 0 depth lookup: unable to get local issuer certificate\n"

    def runner(args: list[str], timeout: float) -> CommandResult:
        return _ok(text)

    raw = verify_chain(_LEAF, [], runner=runner)
    assert raw.status == "incomplete"
    assert raw.openssl_error == "error 20 at 0 depth lookup: unable to get local issuer certificate"
    assert raw.root_common_name == "example.com"


def test_verify_error_18_is_self_signed() -> None:
    text = "depth=0 CN = self.example.com\nerror 18 at 0 depth lookup: self-signed certificate\n"

    def runner(args: list[str], timeout: float) -> CommandResult:
        return _ok(text)

    raw = verify_chain(_LEAF, [], runner=runner)
    assert raw.status == "self_signed"
    assert raw.root_common_name == "self.example.com"
    assert raw.openssl_error is not None
    assert raw.openssl_error.startswith("error 18")


def test_verify_without_a_depth_line_has_no_root_name() -> None:
    def runner(args: list[str], timeout: float) -> CommandResult:
        return _ok("error 21 at 0 depth lookup: unable to verify the first certificate\n")

    raw = verify_chain(_LEAF, [], runner=runner)
    assert raw.status == "incomplete"
    assert raw.root_common_name is None


def test_verify_writes_untrusted_file_and_deletes_the_directory() -> None:
    seen: dict[str, str] = {}

    def runner(args: list[str], timeout: float) -> CommandResult:
        assert args[:6] == [
            "openssl",
            "verify",
            "-no_check_time",
            "-show_chain",
            "-purpose",
            "sslserver",
        ]
        untrusted = args[args.index("-untrusted") + 1]
        leaf = args[-1]
        directory = os.path.dirname(leaf)
        seen["directory"] = directory
        assert os.path.isdir(directory)
        assert os.path.basename(leaf) == "leaf.pem"
        assert os.path.basename(untrusted) == "untrusted.pem"
        assert "example.com" not in leaf
        assert os.stat(directory).st_mode & 0o777 == 0o700
        assert os.stat(leaf).st_mode & 0o777 == 0o600
        assert os.stat(untrusted).st_mode & 0o777 == 0o600
        raise RuntimeError("stop")

    with pytest.raises(RuntimeError, match="stop"):
        verify_chain(_LEAF, [_EXTRA], runner=runner)
    assert not os.path.exists(seen["directory"])
