import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


@dataclass(frozen=True)
class DomainMatch:
    matched: bool
    matched_name: str | None
    source: str | None
    cn: str | None
    san_dns: tuple[str, ...]
    san_ip: tuple[str, ...]
    wildcard: bool


def match_hostname(
    host: str,
    *,
    cn: str | None,
    san_dns: Sequence[str] | None,
    san_ip: Sequence[str] | None,
) -> DomainMatch:
    """比较主机和证书名。名字先收成小写 punycode。某一项转码失败只算这项不能匹配。"""
    cn_name = _normalize(cn)
    dns_names = _normalize_all(san_dns)
    ip_names = _normalize_all(san_ip)
    wildcard = any(_is_wildcard(name) for name in dns_names) or (
        cn_name is not None and _is_wildcard(cn_name)
    )
    host_name = _normalize(host)
    if host_name is None:
        return DomainMatch(False, None, None, cn_name, dns_names, ip_names, wildcard)
    if _is_ip(host_name):
        matched_name = next((item for item in ip_names if item == host_name), None)
        return DomainMatch(
            matched_name is not None,
            matched_name,
            "san" if matched_name is not None else None,
            cn_name,
            dns_names,
            ip_names,
            wildcard,
        )

    if san_dns or san_ip:
        matched_name = _first_match(dns_names, host_name)
        source = "san" if matched_name is not None else None
    elif cn_name is not None:
        matched_name = cn_name if _matches(cn_name, host_name) else None
        source = "cn" if matched_name is not None else None
    else:
        matched_name = None
        source = None
    return DomainMatch(
        matched_name is not None,
        matched_name,
        source,
        cn_name,
        dns_names,
        ip_names,
        wildcard,
    )


def _normalize_all(values: Sequence[str] | None) -> tuple[str, ...]:
    if not values:
        return ()
    names: list[str] = []
    for value in values:
        name = _normalize(value)
        if name is not None:
            names.append(name)
    return tuple(names)


def _normalize(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().rstrip(".").lower()
    if text == "":
        return None
    try:
        encoded = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    encoded = encoded.rstrip(".").lower()
    if encoded == "":
        return None
    return encoded


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _first_match(names: tuple[str, ...], host: str) -> str | None:
    for name in names:
        if _matches(name, host):
            return name
    return None


def _matches(name: str, host: str) -> bool:
    if _is_wildcard(name):
        return _wildcard_matches(name, host)
    return name == host


def _is_wildcard(name: str) -> bool:
    if not name.startswith("*.") or name.count("*") != 1:
        return False
    suffix = name[2:]
    return _labels_ok(suffix)


def _wildcard_matches(pattern: str, host: str) -> bool:
    suffix = pattern[2:]
    tail = "." + suffix
    if not host.endswith(tail) or host == suffix:
        return False
    left = host[: -len(tail)]
    return _label_ok(left) and "." not in left


def _labels_ok(name: str) -> bool:
    if name == "" or len(name) > 253 or name.startswith("-"):
        return False
    return all(_label_ok(label) for label in name.split("."))


def _label_ok(label: str) -> bool:
    if label == "" or len(label) > 63 or label[0] == "-" or label[-1] == "-":
        return False
    return all(ch in _LABEL_CHARS for ch in label)
