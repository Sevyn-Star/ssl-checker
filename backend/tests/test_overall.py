from datetime import datetime, timezone

import pytest

from app.services.overall import Alert, Overall, aggregate
from app.services.risk import Expiry, classify_expiry

_UTC = timezone.utc
_NOW = datetime(2026, 11, 10, tzinfo=_UTC)
_HOST = "example.com"
_INCOMPLETE = "服务器没有提供完整的中间证书，部分客户端无法建立信任。"
_SELF_SIGNED = "这是自签名证书，不在公共信任库中。"
_UNTRUSTED = "证书链无法关联到本机信任的根证书。"
_MISMATCH = "证书不包含 example.com。"


def _expiry(not_before: str, not_after: str) -> Expiry:
    return classify_expiry(
        datetime.fromisoformat(not_before),
        datetime.fromisoformat(not_after),
        _NOW,
    )


def _ok() -> Expiry:
    return _expiry("2026-01-01T00:00:00+00:00", "2026-12-11T00:00:00+00:00")


def _notice() -> Expiry:
    return _expiry("2026-01-01T00:00:00+00:00", "2026-12-10T00:00:00+00:00")


def _today() -> Expiry:
    return _expiry("2026-01-01T00:00:00+00:00", "2026-11-10T12:00:00+00:00")


def _expired() -> Expiry:
    return _expiry("2026-01-01T00:00:00+00:00", "2026-11-09T00:00:00+00:00")


def _not_yet() -> Expiry:
    return _expiry("2026-11-11T00:00:00+00:00", "2027-01-01T00:00:00+00:00")


@pytest.mark.parametrize(
    ("expiry", "matched", "chain", "expected"),
    [
        (_ok(), True, "complete", Overall("valid", "证书有效", ())),
        (
            _notice(),
            True,
            "complete",
            Overall(
                "expiring",
                "即将过期",
                (Alert("notice_30", "证书将在 30 天后过期，建议在 30 天内安排续期。"),),
            ),
        ),
        (
            _today(),
            True,
            "complete",
            Overall(
                "expiring",
                "即将过期",
                (Alert("critical_3", "证书将在今天到期，请立即续期。"),),
            ),
        ),
        (
            _ok(),
            False,
            "complete",
            Overall("mismatch", "域名不匹配", (Alert("mismatch", _MISMATCH),)),
        ),
        (
            _ok(),
            True,
            "incomplete",
            Overall("chain_error", "证书链异常", (Alert("chain_error", _INCOMPLETE),)),
        ),
        (
            _ok(),
            True,
            "self_signed",
            Overall("chain_error", "证书链异常", (Alert("chain_error", _SELF_SIGNED),)),
        ),
        (
            _ok(),
            True,
            "untrusted",
            Overall("chain_error", "证书链异常", (Alert("chain_error", _UNTRUSTED),)),
        ),
        (
            _expired(),
            False,
            "complete",
            Overall(
                "expired",
                "证书过期",
                (
                    Alert("expired", "证书已于 2026-11-09 过期。"),
                    Alert("mismatch", _MISMATCH),
                ),
            ),
        ),
        (
            _not_yet(),
            False,
            "incomplete",
            Overall(
                "not_yet_valid",
                "尚未生效",
                (
                    Alert("not_yet_valid", "证书要到 2026-11-11 才生效。"),
                    Alert("mismatch", _MISMATCH),
                    Alert("chain_error", _INCOMPLETE),
                ),
            ),
        ),
        (
            _notice(),
            True,
            "incomplete",
            Overall(
                "chain_error",
                "证书链异常",
                (
                    Alert("notice_30", "证书将在 30 天后过期，建议在 30 天内安排续期。"),
                    Alert("chain_error", _INCOMPLETE),
                ),
            ),
        ),
        (
            _expired(),
            True,
            "self_signed",
            Overall(
                "expired",
                "证书过期",
                (
                    Alert("expired", "证书已于 2026-11-09 过期。"),
                    Alert("chain_error", _SELF_SIGNED),
                ),
            ),
        ),
    ],
)
def test_aggregate(expiry: Expiry, matched: bool, chain: str, expected: Overall) -> None:
    assert aggregate(_HOST, expiry, matched, chain) == expected


def test_unknown_chain_status_is_rejected() -> None:
    with pytest.raises(ValueError):
        aggregate(_HOST, _ok(), True, "trusted")
