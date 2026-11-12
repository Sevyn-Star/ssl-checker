from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.services.risk import classify_expiry

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)
_UTC = timezone.utc


def _at(value: str) -> datetime:
    if "T" not in value:
        value = f"{value}T00:00:00Z"
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@pytest.mark.parametrize(
    ("not_before", "not_after", "now", "level", "days", "message"),
    [
        ("2026-01-01", "2026-12-11T00:00:00Z", NOW, "ok", 31, ""),
        (
            "2026-01-01",
            "2026-12-10T00:00:00Z",
            NOW,
            "notice_30",
            30,
            "证书将在 30 天后过期，建议在 30 天内安排续期。",
        ),
        (
            "2026-01-01",
            "2026-11-26T00:00:00Z",
            NOW,
            "notice_30",
            16,
            "证书将在 16 天后过期，建议在 30 天内安排续期。",
        ),
        (
            "2026-01-01",
            "2026-11-25T00:00:00Z",
            NOW,
            "warning_15",
            15,
            "剩余有效期不足 15 天，建议尽快续期。",
        ),
        (
            "2026-01-01",
            "2026-11-18T00:00:00Z",
            NOW,
            "warning_15",
            8,
            "剩余有效期不足 15 天，建议尽快续期。",
        ),
        (
            "2026-01-01",
            "2026-11-17T00:00:00Z",
            NOW,
            "warning_7",
            7,
            "剩余有效期不足 7 天，过期风险较高。",
        ),
        (
            "2026-01-01",
            "2026-11-14T00:00:00Z",
            NOW,
            "warning_7",
            4,
            "剩余有效期不足 7 天，过期风险较高。",
        ),
        (
            "2026-01-01",
            "2026-11-13T00:00:00Z",
            NOW,
            "critical_3",
            3,
            "剩余有效期不足 3 天，请立即续期。",
        ),
        (
            "2026-01-01",
            "2026-11-11T00:00:00Z",
            NOW,
            "critical_3",
            1,
            "剩余有效期不足 3 天，请立即续期。",
        ),
        (
            "2026-01-01",
            "2026-11-10T12:00:00Z",
            NOW,
            "critical_3",
            0,
            "证书将在今天到期，请立即续期。",
        ),
        (
            "2026-01-01",
            "2026-11-10T00:00:00Z",
            datetime(2026, 11, 10, 0, 0, 1, tzinfo=_UTC),
            "expired",
            0,
            "证书已于 2026-11-10 过期。",
        ),
        (
            "2026-01-01",
            "2026-11-10T00:00:00Z",
            NOW,
            "expired",
            0,
            "证书已于 2026-11-10 过期。",
        ),
        (
            "2026-01-01",
            "2026-11-09T00:00:00Z",
            NOW,
            "expired",
            -1,
            "证书已于 2026-11-09 过期。",
        ),
        (
            "2026-11-11",
            "2027-01-01",
            NOW,
            "not_yet_valid",
            None,
            "证书要到 2026-11-11 才生效。",
        ),
    ],
)
def test_classify_expiry(
    not_before: str,
    not_after: str,
    now: datetime,
    level: str,
    days: int | None,
    message: str,
) -> None:
    got = classify_expiry(_at(not_before), _at(not_after), now)
    assert got.risk_level == level
    assert got.remaining_days == days
    assert got.message == message
    if level == "notice_30" and days == 30:
        assert "30 天" in got.message


def test_dates_use_utc_not_the_offset_date() -> None:
    plus_8 = timezone(timedelta(hours=8))
    got = classify_expiry(
        datetime(2026, 1, 1, tzinfo=_UTC),
        datetime(2026, 12, 10, tzinfo=_UTC),
        datetime(2026, 11, 10, 7, tzinfo=plus_8),
    )
    assert got.remaining_days == 31
    assert got.risk_level == "ok"
    assert got.message == ""


def test_naive_datetime_is_rejected() -> None:
    aware = datetime(2026, 11, 10, tzinfo=_UTC)
    naive = datetime(2026, 11, 10)
    with pytest.raises(ValueError):
        classify_expiry(naive, aware, aware)
    with pytest.raises(ValueError):
        classify_expiry(aware, naive, aware)
    with pytest.raises(ValueError):
        classify_expiry(aware, aware, naive)


def test_classify_expiry_does_not_read_the_clock() -> None:
    source = Path(classify_expiry.__code__.co_filename).read_text(encoding="utf-8")
    assert "datetime.now" not in source
    assert ".today(" not in source
