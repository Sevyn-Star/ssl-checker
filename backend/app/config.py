import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    check_timeout_seconds: int
    cache_ttl_seconds: int
    error_cache_ttl_seconds: int
    rate_limit_per_minute: int
    trust_proxy: bool
    ca_bundle: str


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"{name} 必须是整数") from exc


def _trust_proxy() -> bool:
    raw = os.environ.get("TRUST_PROXY", "0").strip()
    if raw in ("", "0"):
        return False
    if raw == "1":
        return True
    raise RuntimeError("TRUST_PROXY 只能是 0 或 1")


def _ca_bundle() -> str:
    explicit = os.environ.get("CA_BUNDLE", "").strip()
    if explicit:
        return explicit
    for candidate in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
    ):
        if os.path.isfile(candidate):
            return candidate
    return ""


def load_settings() -> Settings:
    return Settings(
        check_timeout_seconds=_int_env("CHECK_TIMEOUT_SECONDS", 10),
        cache_ttl_seconds=_int_env("CACHE_TTL_SECONDS", 300),
        error_cache_ttl_seconds=_int_env("ERROR_CACHE_TTL_SECONDS", 30),
        rate_limit_per_minute=_int_env("RATE_LIMIT_PER_MINUTE", 10),
        trust_proxy=_trust_proxy(),
        ca_bundle=_ca_bundle(),
    )


settings = load_settings()
