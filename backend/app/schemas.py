from datetime import datetime, timezone

from pydantic import BaseModel, field_serializer


def utc_z(value: datetime) -> str:
    """收成 UTC，秒级，用 Z 结尾。"""
    utc = value.astimezone(timezone.utc).replace(microsecond=0)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


class CheckRequest(BaseModel):
    host: str
    refresh: bool = False


class ErrorInfo(BaseModel):
    code: str
    message: str


class FailureResponse(BaseModel):
    ok: bool = False
    host: str
    error: ErrorInfo


class OverallBody(BaseModel):
    status: str
    label: str


class ValidityBody(BaseModel):
    not_before: datetime
    not_after: datetime
    remaining_days: int | None
    risk_level: str

    @field_serializer("not_before", "not_after")
    def serialize_times(self, value: datetime) -> str:
        return utc_z(value)


class PartyBody(BaseModel):
    organization: str | None = None
    common_name: str | None
    distinguished_name: str


class SubjectBody(BaseModel):
    common_name: str | None
    organization: str | None
    distinguished_name: str


class DomainMatchBody(BaseModel):
    matched: bool
    matched_name: str | None
    source: str | None
    cn: str | None
    san_dns: list[str]
    san_ip: list[str]
    wildcard: bool


class ChainItemBody(BaseModel):
    role: str
    role_label: str
    common_name: str
    status: str
    status_label: str


class ChainBody(BaseModel):
    status: str
    label: str
    openssl_error: str | None
    items: list[ChainItemBody]


class TlsBody(BaseModel):
    version: str | None
    cipher_suite: str | None


class PublicKeyBody(BaseModel):
    algorithm: str
    detail: str


class AlertBody(BaseModel):
    level: str
    message: str


class CheckSuccess(BaseModel):
    ok: bool = True
    cached: bool
    host: str
    display_host: str
    resolved_ip: str
    checked_at: datetime
    elapsed_ms: int
    overall: OverallBody
    validity: ValidityBody
    certificate_type: str
    certificate_type_label: str
    certificate_type_source: str
    issuer: PartyBody
    subject: SubjectBody
    domain_match: DomainMatchBody
    chain: ChainBody
    tls: TlsBody
    public_key: PublicKeyBody
    serial_hex: str
    fingerprint_sha256: str
    alerts: list[AlertBody]

    @field_serializer("checked_at")
    def serialize_checked_at(self, value: datetime) -> str:
        return utc_z(value)
