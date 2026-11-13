import copy
import time
from dataclasses import dataclass


@dataclass
class _Entry:
    body: dict
    expires_at: float


_store: dict[str, _Entry] = {}


def get(key: str, *, now: float | None = None) -> dict | None:
    """命中且未过期时返回副本。成功结果的 cached 改为 true。"""
    current = time.monotonic() if now is None else now
    entry = _store.get(key)
    if entry is None:
        return None
    if entry.expires_at <= current:
        del _store[key]
        return None
    body = copy.deepcopy(entry.body)
    if "cached" in body:
        body["cached"] = True
    return body


def set(key: str, body: dict, ttl: float, *, now: float | None = None) -> None:
    """存一份副本。ttl 由调用方决定，单位是秒。"""
    current = time.monotonic() if now is None else now
    _store[key] = _Entry(copy.deepcopy(body), current + ttl)


def clear() -> None:
    _store.clear()
