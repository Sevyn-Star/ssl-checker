from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Expiry:
    remaining_days: int | None
    risk_level: str
    message: str


def classify_expiry(not_before: datetime, not_after: datetime, now: datetime) -> Expiry:
    """按 UTC 时刻和日期判断有效期。不读系统时钟。"""
    not_before = _as_utc(not_before, "not_before")
    not_after = _as_utc(not_after, "not_after")
    now = _as_utc(now, "now")

    if now >= not_after:
        remaining = _days_between(not_after, now)
        day = not_after.date().isoformat()
        return Expiry(remaining, "expired", f"证书已于 {day} 过期。")
    if now < not_before:
        day = not_before.date().isoformat()
        return Expiry(None, "not_yet_valid", f"证书要到 {day} 才生效。")

    remaining = _days_between(not_after, now)
    if remaining <= 0:
        return Expiry(remaining, "critical_3", "证书将在今天到期，请立即续期。")
    if remaining <= 3:
        return Expiry(remaining, "critical_3", "剩余有效期不足 3 天，请立即续期。")
    if remaining <= 7:
        return Expiry(remaining, "warning_7", "剩余有效期不足 7 天，过期风险较高。")
    if remaining <= 15:
        return Expiry(remaining, "warning_15", "剩余有效期不足 15 天，建议尽快续期。")
    if remaining <= 30:
        return Expiry(remaining, "notice_30", f"证书将在 {remaining} 天后过期，建议在 30 天内安排续期。")
    return Expiry(remaining, "ok", "")


def _as_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{name} 必须带时区")
    return value.astimezone(timezone.utc)


def _days_between(not_after: datetime, now: datetime) -> int:
    return (not_after.date() - now.date()).days
