from dataclasses import dataclass

from app.services.risk import Expiry

_LABELS = {
    "not_yet_valid": "尚未生效",
    "expired": "证书过期",
    "mismatch": "域名不匹配",
    "chain_error": "证书链异常",
    "expiring": "即将过期",
    "valid": "证书有效",
}

_CHAIN_MESSAGES = {
    "incomplete": "服务器没有提供完整的中间证书，部分客户端无法建立信任。",
    "self_signed": "这是自签名证书，不在公共信任库中。",
    "untrusted": "证书链无法关联到本机信任的根证书。",
}

_CHAIN_STATUSES = frozenset({"complete", *_CHAIN_MESSAGES})


@dataclass(frozen=True)
class Alert:
    level: str
    message: str


@dataclass(frozen=True)
class Overall:
    status: str
    label: str
    alerts: tuple[Alert, ...]


def aggregate(host: str, expiry: Expiry, matched: bool, chain_status: str) -> Overall:
    """按从重到轻合成总状态。提醒按有效期、域名、证书链保留，不随胶囊删减。"""
    if chain_status not in _CHAIN_STATUSES:
        raise ValueError(f"未知的证书链状态: {chain_status}")

    alerts: list[Alert] = []
    if expiry.risk_level != "ok":
        alerts.append(Alert(expiry.risk_level, expiry.message))
    if not matched:
        alerts.append(Alert("mismatch", f"证书不包含 {host}。"))
    if chain_status != "complete":
        alerts.append(Alert("chain_error", _CHAIN_MESSAGES[chain_status]))

    if expiry.risk_level == "not_yet_valid":
        status = "not_yet_valid"
    elif expiry.risk_level == "expired":
        status = "expired"
    elif not matched:
        status = "mismatch"
    elif chain_status != "complete":
        status = "chain_error"
    elif expiry.risk_level != "ok":
        status = "expiring"
    else:
        status = "valid"
    return Overall(status, _LABELS[status], tuple(alerts))
