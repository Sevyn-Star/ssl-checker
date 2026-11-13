import time
from datetime import datetime, timezone

from app.config import settings
from app.schemas import (
    AlertBody,
    ChainBody,
    ChainItemBody,
    CheckSuccess,
    DomainMatchBody,
    OverallBody,
    PartyBody,
    PublicKeyBody,
    SubjectBody,
    TlsBody,
    ValidityBody,
)
from app.security import MESSAGES, ResolveFailed, normalize_host, resolve_public_ips
from app.services import cache
from app.services.chain import build_chain
from app.services.domain_match import match_hostname
from app.services.openssl_client import FetchError, fetch_peer, run_command, verify_chain
from app.services.overall import aggregate
from app.services.parser import parse_certificate
from app.services.risk import classify_expiry

_TYPE_LABELS = {
    "ev": "EV SSL",
    "ov": "OV SSL",
    "dv": "DV SSL",
}

_MAX_ADDRESSES = 2


def check_host(raw: str, *, refresh: bool = False, now: datetime | None = None) -> dict:
    """按固定顺序完成一次检测。refresh 不读缓存，结束后仍写回。"""
    started = time.perf_counter()
    moment = now if now is not None else datetime.now(timezone.utc)
    host = normalize_host(raw)
    if not refresh:
        cached = cache.get(host.host)
        if cached is not None:
            return cached

    try:
        addresses = resolve_public_ips(host)
    except ResolveFailed as exc:
        return _failure(host.host, exc.code)

    material = None
    connected: str | None = None
    last_code = "handshake_failed"
    for ip in addresses[:_MAX_ADDRESSES]:
        try:
            material = fetch_peer(
                ip,
                None if host.is_ip else host.host,
                timeout=float(settings.check_timeout_seconds),
            )
        except FetchError as exc:
            last_code = exc.code
            continue
        connected = ip
        break
    if material is None or connected is None:
        return _failure(host.host, last_code)

    try:
        leaf = parse_certificate(material.pems[0])
        intermediates = [parse_certificate(pem) for pem in material.pems[1:]]
    except ValueError:
        return _failure(host.host, "no_certificate")

    matched = match_hostname(
        host.host,
        cn=leaf.subject_cn,
        san_dns=leaf.san_dns,
        san_ip=leaf.san_ip,
    )
    verified = verify_chain(material.pems[0], list(material.pems[1:]), runner=run_command)
    expiry = classify_expiry(leaf.not_before, leaf.not_after, moment)
    chain = build_chain(leaf, intermediates, verified, moment)
    overall = aggregate(host.display_host, expiry, matched.matched, chain.status)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    body = _success(host, connected, moment, elapsed_ms, leaf, matched, expiry, overall, chain, material)
    cache.set(host.host, body, settings.cache_ttl_seconds)
    return body


def _failure(host: str, code: str) -> dict:
    body = {
        "ok": False,
        "host": host,
        "error": {"code": code, "message": MESSAGES[code]},
    }
    cache.set(host, body, settings.error_cache_ttl_seconds)
    return body


def _success(host, connected, moment, elapsed_ms, leaf, matched, expiry, overall, chain, material) -> dict:
    payload = CheckSuccess(
        ok=True,
        cached=False,
        host=host.host,
        display_host=host.display_host,
        resolved_ip=connected,
        checked_at=moment,
        elapsed_ms=elapsed_ms,
        overall=OverallBody(status=overall.status, label=overall.label),
        validity=ValidityBody(
            not_before=leaf.not_before,
            not_after=leaf.not_after,
            remaining_days=expiry.remaining_days,
            risk_level=expiry.risk_level,
        ),
        certificate_type=leaf.certificate_type,
        certificate_type_label=_TYPE_LABELS[leaf.certificate_type],
        certificate_type_source=leaf.certificate_type_source,
        issuer=PartyBody(
            organization=leaf.issuer_organization,
            common_name=leaf.issuer_cn,
            distinguished_name=leaf.issuer_dn,
        ),
        subject=SubjectBody(
            common_name=leaf.subject_cn,
            organization=leaf.subject_organization,
            distinguished_name=leaf.subject_dn,
        ),
        domain_match=DomainMatchBody(
            matched=matched.matched,
            matched_name=matched.matched_name,
            source=matched.source,
            cn=matched.cn,
            san_dns=list(matched.san_dns),
            san_ip=list(matched.san_ip),
            wildcard=matched.wildcard,
        ),
        chain=ChainBody(
            status=chain.status,
            label=chain.label,
            openssl_error=chain.openssl_error,
            items=[
                ChainItemBody(
                    role=item.role,
                    role_label=item.role_label,
                    common_name=item.common_name,
                    status=item.status,
                    status_label=item.status_label,
                )
                for item in chain.items
            ],
        ),
        tls=TlsBody(version=material.protocol, cipher_suite=material.cipher_suite),
        public_key=PublicKeyBody(
            algorithm=leaf.public_key.algorithm,
            detail=leaf.public_key.detail,
        ),
        serial_hex=leaf.serial_hex,
        fingerprint_sha256=leaf.fingerprint_sha256,
        alerts=[AlertBody(level=item.level, message=item.message) for item in overall.alerts],
    )
    return payload.model_dump(mode="json")
