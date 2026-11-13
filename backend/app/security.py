import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

MESSAGES: dict[str, str] = {
    "invalid_host": "请输入域名，例如 example.com。",
    "port_not_allowed": "目前只检测 443 端口。",
    "blocked_host": "这个地址不能检测。",
    "dns_failed": "无法解析这个域名。",
    "no_public_ip": "这个域名没有可用的公网地址。",
    "connect_failed": "无法连上 443 端口。",
    "timeout": "连接超时，目标没有在 10 秒内完成 TLS 握手。",
    "handshake_failed": "TLS 握手失败。",
    "no_certificate": "服务器没有返回证书。",
    "rate_limited": "检测过于频繁，请稍后再试。",
}

_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal")

# is_private / is_global 盖不住的范围：共享地址、文档地址、站点本地。
_V4_BLOCKED = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("169.254.0.0/16"),
)
_V6_BLOCKED = (
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fec0::/10"),
    ipaddress.ip_network("2001:db8::/32"),
)


class HostRejected(Exception):
    code: str
    message: str

    def __init__(self, code: str) -> None:
        self.code = code
        self.message = MESSAGES[code]
        super().__init__(self.message)


class ResolveFailed(Exception):
    code: str
    message: str

    def __init__(self, code: str) -> None:
        self.code = code
        self.message = MESSAGES[code]
        super().__init__(self.message)


@dataclass(frozen=True)
class NormalizedHost:
    host: str
    display_host: str
    is_ip: bool


def is_public_ip(ip: str) -> bool:
    """公网单播地址才返回真。文档地址和共享地址也不算。"""
    addr = _parse_ip(ip)
    if addr is None:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return False
    blocked = _V4_BLOCKED if addr.version == 4 else _V6_BLOCKED
    return not any(addr in network for network in blocked)


def normalize_host(raw: str) -> NormalizedHost:
    """收成可放进 -servername 的主机名。拒绝时抛 HostRejected，不查 DNS。"""
    if not isinstance(raw, str):
        raise HostRejected("invalid_host")
    text = raw.strip()
    if text == "" or any(ch.isspace() for ch in text):
        raise HostRejected("invalid_host")

    host, port = _split_host_port(_extract_hostport(text))
    if port not in (None, 443):
        raise HostRejected("port_not_allowed")
    if host == "":
        raise HostRejected("invalid_host")

    ascii_host = _idna_ascii(host)
    parsed = _parse_ip(ascii_host)
    if parsed is not None:
        if not is_public_ip(str(parsed)):
            raise HostRejected("blocked_host")
        canonical = str(parsed)
        return NormalizedHost(canonical, canonical, True)

    _validate_domain(ascii_host)
    return NormalizedHost(ascii_host, _display_host(ascii_host), False)


def resolve_public_ips(host: NormalizedHost) -> list[str]:
    """域名解析出的公网地址。IPv4 在前，同族保持原顺序。IP 字面量不再解析。"""
    if host.is_ip:
        return [host.host]
    try:
        infos = socket.getaddrinfo(host.host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolveFailed("dns_failed") from exc

    ipv4: list[str] = []
    ipv6: list[str] = []
    seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for info in infos:
        parsed = _parse_ip(info[4][0].split("%", 1)[0])
        if parsed is None or parsed in seen or not is_public_ip(str(parsed)):
            continue
        seen.add(parsed)
        rendered = str(parsed)
        if parsed.version == 4:
            ipv4.append(rendered)
        else:
            ipv6.append(rendered)
    if not ipv4 and not ipv6:
        raise ResolveFailed("no_public_ip")
    return ipv4 + ipv6


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _extract_hostport(text: str) -> str:
    if "://" in text:
        try:
            parts = urlsplit(text)
        except ValueError as exc:
            raise HostRejected("invalid_host") from exc
        if parts.username is not None or parts.password is not None:
            raise HostRejected("invalid_host")
        if parts.netloc == "" or "@" in parts.netloc:
            raise HostRejected("invalid_host")
        return parts.netloc
    text = text.split("?", 1)[0]
    text = text.split("/", 1)[0]
    if text == "":
        raise HostRejected("invalid_host")
    return text


def _split_host_port(text: str) -> tuple[str, int | None]:
    if text.startswith("["):
        end = text.find("]")
        host = text[1:end] if end > 1 else ""
        if end < 0 or not _is_ipv6(host):
            raise HostRejected("invalid_host")
        rest = text[end + 1 :]
        if rest == "":
            return host, None
        if not rest.startswith(":") or not rest[1:].isdigit():
            raise HostRejected("invalid_host")
        return host, int(rest[1:])

    if ":" not in text:
        return text, None
    host, _, maybe_port = text.rpartition(":")
    if host and maybe_port.isdigit() and (":" not in host or _is_ipv6(host)):
        return host, int(maybe_port)
    raise HostRejected("invalid_host")


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _idna_ascii(host: str) -> str:
    try:
        encoded = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise HostRejected("invalid_host") from exc
    encoded = encoded.rstrip(".").lower()
    if encoded == "":
        raise HostRejected("invalid_host")
    return encoded


def _display_host(ascii_host: str) -> str:
    try:
        return ascii_host.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise HostRejected("invalid_host") from exc


def _validate_domain(host: str) -> None:
    if len(host) > 253:
        raise HostRejected("invalid_host")
    labels = host.split(".")
    for label in labels:
        if len(label) > 63 or not _label_ok(label):
            raise HostRejected("invalid_host")
    if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise HostRejected("blocked_host")
    if len(labels) < 2:
        raise HostRejected("invalid_host")


def _label_ok(label: str) -> bool:
    if not label or label[0] == "-" or label[-1] == "-":
        return False
    return all(ch in _LABEL_CHARS for ch in label)
