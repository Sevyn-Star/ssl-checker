from dataclasses import dataclass
from datetime import datetime

from app.services.openssl_client import VerifyRaw
from app.services.parser import ParsedCert

_LABELS = {
    "complete": "完整",
    "incomplete": "不完整",
    "self_signed": "不受信任",
    "untrusted": "不受信任",
}


@dataclass(frozen=True)
class ChainItem:
    role: str
    role_label: str
    common_name: str
    status: str
    status_label: str


@dataclass(frozen=True)
class Chain:
    status: str
    label: str
    openssl_error: str | None
    items: tuple[ChainItem, ...]


def build_chain(
    leaf: ParsedCert,
    intermediates: list[ParsedCert],
    verify: VerifyRaw,
    now: datetime,
) -> Chain:
    """按已发送证书的 DN 衔接。名字没接上时，验证成功也记为不完整。"""
    linked = _linked(leaf, intermediates)
    if verify.status == "complete" and not linked:
        status = "incomplete"
    else:
        status = verify.status
    items = [_leaf_item(leaf, now)]
    if status != "self_signed":
        items.extend(_following_items(leaf, intermediates, verify, status))
    return Chain(status, _LABELS[status], verify.openssl_error, tuple(items))


def _linked(leaf: ParsedCert, intermediates: list[ParsedCert]) -> bool:
    if not intermediates:
        return False
    current = leaf
    for cert in intermediates:
        if current.issuer_dn != cert.subject_dn:
            return False
        current = cert
    return True


def _following_items(
    leaf: ParsedCert,
    intermediates: list[ParsedCert],
    verify: VerifyRaw,
    status: str,
) -> list[ChainItem]:
    items: list[ChainItem] = []
    current = leaf
    for cert in intermediates:
        if _is_anchor(cert, verify.root_common_name):
            continue
        if current.issuer_dn == cert.subject_dn:
            items.append(
                ChainItem(
                    "intermediate",
                    "中间 CA 证书",
                    cert.subject_cn or "",
                    "valid",
                    "有效",
                )
            )
            current = cert
            continue
        items.append(ChainItem("intermediate", "中间 CA 证书", "", "missing", "缺失"))
        break
    items.extend(_root_item(status, verify.root_common_name))
    return items


def _root_item(status: str, root_common_name: str | None) -> list[ChainItem]:
    if status == "complete":
        return [
            ChainItem(
                "root",
                "根 CA 证书",
                root_common_name or "",
                "trusted",
                "可信",
            )
        ]
    if status in {"incomplete", "untrusted"} and not root_common_name:
        return [ChainItem("root", "根 CA 证书", "", "not_found", "未找到")]
    return []


def _leaf_item(leaf: ParsedCert, now: datetime) -> ChainItem:
    if now < leaf.not_before:
        status, label = "not_yet_valid", "尚未生效"
    elif now >= leaf.not_after:
        status, label = "expired", "已过期"
    else:
        status, label = "valid", "有效"
    return ChainItem("leaf", "服务器证书", leaf.subject_cn or "", status, label)


def _is_anchor(cert: ParsedCert, root_common_name: str | None) -> bool:
    if root_common_name is None:
        return False
    return cert.subject_dn == cert.issuer_dn and cert.subject_cn == root_common_name
