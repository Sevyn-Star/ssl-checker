import time
from collections.abc import Callable

_WINDOW_SECONDS = 60.0


class Limiter:
    """按客户端 IP 滑动记录最近 60 秒的请求。"""

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._hits: dict[str, list[float]] = {}

    def allow(self, ip: str, limit: int) -> bool:
        now = self._clock()
        recent = [stamp for stamp in self._hits.get(ip, []) if now - stamp < _WINDOW_SECONDS]
        if len(recent) >= limit:
            self._hits[ip] = recent
            return False
        recent.append(now)
        self._hits[ip] = recent
        return True

    def clear(self) -> None:
        self._hits.clear()


limiter = Limiter()
