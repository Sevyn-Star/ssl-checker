import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.config import settings
from app.schemas import CheckRequest, ErrorInfo, FailureResponse
from app.security import MESSAGES, HostRejected
from app.services.checker import check_host
from app.services.limiter import limiter

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/api/v1/check")
async def check(request: Request) -> JSONResponse:
    started = time.perf_counter()
    payload, rejected = await _payload(request)
    if rejected is not None:
        return _json(400, rejected, started)
    assert payload is not None
    if not limiter.allow(_client_ip(request), settings.rate_limit_per_minute):
        return _json(429, _error(payload.host, "rate_limited"), started)
    try:
        body = check_host(payload.host, refresh=payload.refresh)
    except HostRejected as exc:
        return _json(400, _error(payload.host, exc.code), started)
    _log(body, _elapsed(started))
    return JSONResponse(status_code=200, content=body)


def _client_ip(request: Request) -> str:
    """默认只用连接上来的地址。TRUST_PROXY=1 时才信 X-Forwarded-For 的第一段。"""
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded is not None:
            first = forwarded.split(",", 1)[0].strip()
            if first:
                return first
    client = request.client
    if client is not None and client.host:
        return client.host
    return "unknown"


async def _payload(request: Request) -> tuple[CheckRequest | None, dict | None]:
    try:
        raw = await request.json()
    except Exception:
        return None, _error("", "invalid_host")
    if not isinstance(raw, dict):
        return None, _error("", "invalid_host")
    try:
        return CheckRequest.model_validate(raw), None
    except ValidationError:
        host = raw.get("host")
        return None, _error(host if isinstance(host, str) else "", "invalid_host")


def _error(host: str, code: str) -> dict:
    return FailureResponse(
        host=host,
        error=ErrorInfo(code=code, message=MESSAGES[code]),
    ).model_dump()


def _json(status_code: int, body: dict, started: float) -> JSONResponse:
    _log(body, _elapsed(started))
    return JSONResponse(status_code=status_code, content=body)


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _log(body: dict, elapsed_ms: int) -> None:
    if body.get("ok") is True:
        overall = body.get("overall") or {}
        validity = body.get("validity") or {}
        chain = body.get("chain") or {}
        days = validity.get("remaining_days")
        logger.info(
            "host=%s resolved_ip=%s status=%s remaining_days=%s chain=%s elapsed_ms=%s",
            body.get("host", "-"),
            body.get("resolved_ip", "-"),
            overall.get("status", "-"),
            "-" if days is None else days,
            chain.get("status", "-"),
            body.get("elapsed_ms", elapsed_ms),
        )
        return
    error = body.get("error") or {}
    logger.info(
        "host=%s resolved_ip=%s status=%s remaining_days=%s chain=%s elapsed_ms=%s",
        body.get("host", "-"),
        "-",
        error.get("code", "-"),
        "-",
        "-",
        elapsed_ms,
    )
