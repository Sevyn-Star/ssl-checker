import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_PROTOCOL_RE = re.compile(r"^\s*Protocol\s*:\s*(\S+)\s*$", re.MULTILINE)
_CIPHER_RE = re.compile(r"^\s*Cipher\s*:\s*(.*?)\s*$", re.MULTILINE)
_SESSION_RE = re.compile(r"^\s*New,\s*(\S+),\s*Cipher is\s*(\S+)\s*$", re.MULTILINE)
_ERROR_CODE_RE = re.compile(r"error (\d+)", re.IGNORECASE)
_ERROR_LINE_RE = re.compile(r"error \d+.*", re.IGNORECASE)
_DEPTH_RE = re.compile(r"^depth=(\d+)\s*:?\s*(.*)$", re.MULTILINE)
_CN_RE = re.compile(r"CN\s*=\s*(.*)", re.IGNORECASE)
_NEXT_RDN_RE = re.compile(r"\s*,\s*[A-Za-z][A-Za-z0-9]*\s*=")
_OK_RE = re.compile(r": OK\b")

_PROTOCOLS = {
    "TLSv1.3": "TLS 1.3",
    "TLSv1.2": "TLS 1.2",
    "TLSv1.1": "TLS 1.1",
    "TLSv1": "TLS 1.0",
    "SSLv3": "SSL 3",
}
_VERIFY_TIMEOUT = 10.0


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool


@dataclass(frozen=True)
class PeerMaterial:
    pems: tuple[str, ...]
    protocol: str | None
    cipher_suite: str | None


@dataclass(frozen=True)
class VerifyRaw:
    status: str
    openssl_error: str | None
    root_common_name: str | None


class FetchError(Exception):
    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


Runner = Callable[..., CommandResult]


def run_command(args: list[str], *, timeout: float) -> CommandResult:
    """用参数数组调用命令。超时变成结果，不向外抛。"""
    try:
        completed = subprocess.run(
            args,
            input=b"",
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            _text(exc.stdout),
            _text(exc.stderr),
            -1,
            True,
        )
    return CommandResult(
        _text(completed.stdout),
        _text(completed.stderr),
        completed.returncode,
        False,
    )


def fetch_peer(
    ip: str,
    hostname: str | None,
    *,
    timeout: float,
    runner: Runner = run_command,
) -> PeerMaterial:
    """取出对方证书、协议和套件。没有证书时抛 FetchError。"""
    args = ["openssl", "s_client", "-connect", _connect_target(ip), "-showcerts"]
    if hostname is not None:
        args.extend(["-servername", hostname])
    result = runner(args, timeout=timeout)
    pems = tuple(_PEM_RE.findall(result.stdout))
    if not pems:
        raise FetchError(_failure_code(result))
    protocol, cipher = _peer_session(result.stdout, result.stderr)
    return PeerMaterial(pems, protocol, cipher)


def verify_chain(
    leaf_pem: str,
    intermediate_pems: list[str],
    *,
    runner: Runner,
) -> VerifyRaw:
    """在临时目录里验证链。目录在成功和异常时都会删除。"""
    directory = tempfile.mkdtemp()
    try:
        os.chmod(directory, 0o700)
        leaf_path = os.path.join(directory, "leaf.pem")
        _write_secret(leaf_path, leaf_pem)
        args = [
            "openssl",
            "verify",
            "-no_check_time",
            "-show_chain",
            "-purpose",
            "sslserver",
        ]
        if intermediate_pems:
            untrusted_path = os.path.join(directory, "untrusted.pem")
            _write_secret(untrusted_path, "\n".join(intermediate_pems))
            args.extend(["-untrusted", untrusted_path])
        args.append(leaf_path)
        result = runner(args, timeout=_VERIFY_TIMEOUT)
        return _interpret_verify(result.stdout, result.stderr)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _connect_target(ip: str) -> str:
    if ":" in ip:
        return f"[{ip.strip('[]')}]:443"
    return f"{ip}:443"


def _failure_code(result: CommandResult) -> str:
    if result.timed_out:
        return "timeout"
    blob = f"{result.stdout}\n{result.stderr}".lower()
    if "connection refused" in blob or "errno=61" in blob or "errno=111" in blob:
        return "connect_failed"
    if "no peer certificate" in blob:
        return "no_certificate"
    return "handshake_failed"


def _peer_session(stdout: str, stderr: str) -> tuple[str | None, str | None]:
    """OpenSSL 3.2 起分行打印 Protocol 和 Cipher。3.0 把两者写在 New 那一行。"""
    protocol = _search(_PROTOCOL_RE, stdout, stderr)
    cipher = _search(_CIPHER_RE, stdout, stderr)
    if protocol is not None and cipher is not None:
        return _map_protocol(protocol), cipher
    for text in (stdout, stderr):
        match = _SESSION_RE.search(text)
        if match is None:
            continue
        if protocol is None:
            protocol = match.group(1)
        if cipher is None:
            cipher = match.group(2)
        break
    return _map_protocol(protocol), cipher


def _search(pattern: re.Pattern[str], stdout: str, stderr: str) -> str | None:
    for text in (stdout, stderr):
        match = pattern.search(text)
        if match:
            return match.group(1).strip()
    return None


def _map_protocol(raw: str | None) -> str | None:
    if raw is None:
        return None
    return _PROTOCOLS.get(raw, raw)


def _interpret_verify(stdout: str, stderr: str) -> VerifyRaw:
    text = f"{stdout}\n{stderr}"
    codes = [int(code) for code in _ERROR_CODE_RE.findall(text)]
    if any(code in (18, 19) for code in codes):
        status = "self_signed"
    elif any(code in (20, 21) for code in codes):
        status = "incomplete"
    elif codes:
        status = "untrusted"
    elif _OK_RE.search(text):
        status = "complete"
    else:
        status = "untrusted"
    if status == "complete":
        error = None
    else:
        line = _ERROR_LINE_RE.search(text)
        error = line.group(0).strip() if line else None
    return VerifyRaw(status, error, _root_common_name(text))


def _root_common_name(text: str) -> str | None:
    chosen: str | None = None
    depth = -1
    for match in _DEPTH_RE.finditer(text):
        current = int(match.group(1))
        if current >= depth:
            depth = current
            chosen = match.group(2).strip()
    if not chosen:
        return None
    cn = _cn_value(chosen)
    if cn:
        return cn
    if ":" in chosen:
        chosen = chosen.split(":", 1)[1]
    chosen = chosen.split("(", 1)[0].strip()
    return chosen or None


def _cn_value(line: str) -> str | None:
    match = _CN_RE.search(line)
    if not match:
        return None
    value = _NEXT_RDN_RE.split(match.group(1), maxsplit=1)[0].strip()
    return value or None


def _write_secret(path: str, text: str) -> None:
    payload = text if text.endswith("\n") else f"{text}\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _text(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", "replace")
