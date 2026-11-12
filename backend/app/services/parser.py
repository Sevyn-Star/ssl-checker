from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_POLICY_TYPES = (
    ("2.23.140.1.1", "ev"),
    ("2.23.140.1.2.2", "ov"),
    ("2.23.140.1.2.1", "dv"),
)


@dataclass(frozen=True)
class PublicKey:
    algorithm: str
    detail: str


@dataclass(frozen=True)
class ParsedCert:
    not_before: datetime
    not_after: datetime
    subject_cn: str | None
    subject_organization: str | None
    issuer_cn: str | None
    issuer_organization: str | None
    subject_dn: str
    issuer_dn: str
    san_dns: tuple[str, ...]
    san_ip: tuple[str, ...]
    serial_hex: str
    fingerprint_sha256: str
    public_key: PublicKey
    policy_oids: tuple[str, ...]
    is_ca: bool
    certificate_type: str
    certificate_type_source: str


def parse_certificate(pem: str) -> ParsedCert:
    """把一张 PEM 证书读成字段。解不开时抛 ValueError。"""
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("无法解析证书") from exc

    subject_organization = _attr(cert.subject, x509.NameOID.ORGANIZATION_NAME)
    policy_oids = _policy_oids(cert)
    certificate_type, certificate_type_source = classify_type(policy_oids, subject_organization)
    san_dns, san_ip = _subject_alt_names(cert)
    return ParsedCert(
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        subject_cn=_attr(cert.subject, x509.NameOID.COMMON_NAME),
        subject_organization=subject_organization,
        issuer_cn=_attr(cert.issuer, x509.NameOID.COMMON_NAME),
        issuer_organization=_attr(cert.issuer, x509.NameOID.ORGANIZATION_NAME),
        subject_dn=cert.subject.rfc4514_string(),
        issuer_dn=cert.issuer.rfc4514_string(),
        san_dns=san_dns,
        san_ip=san_ip,
        serial_hex=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        public_key=_public_key(cert.public_key()),
        policy_oids=policy_oids,
        is_ca=_is_ca(cert),
        certificate_type=certificate_type,
        certificate_type_source=certificate_type_source,
    )


def classify_type(
    policy_oids: tuple[str, ...] | list[str],
    subject_organization: str | None,
) -> tuple[str, str]:
    """多个策略 OID 时按 EV、OV、DV 取最高的一个。没有这些 OID 时看组织名。"""
    present = set(policy_oids)
    for oid, kind in _POLICY_TYPES:
        if oid in present:
            return kind, "policy"
    if subject_organization:
        return "ov", "subject"
    return "dv", "subject"


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return None
    value = attrs[0].value
    if isinstance(value, str):
        return value
    return str(value)


def _subject_alt_names(cert: x509.Certificate) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return (), ()
    dns = tuple(san.get_values_for_type(x509.DNSName))
    ips = tuple(str(ip) for ip in san.get_values_for_type(x509.IPAddress))
    return dns, ips


def _policy_oids(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(policy.policy_identifier.dotted_string for policy in policies)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return constraints.ca


def _public_key(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey | object) -> PublicKey:
    if isinstance(key, rsa.RSAPublicKey):
        return PublicKey("RSA", str(key.key_size))
    if isinstance(key, ec.EllipticCurvePublicKey):
        return PublicKey("ECDSA", _curve_name(key.curve))
    return PublicKey(type(key).__name__, "")


def _curve_name(curve: ec.EllipticCurve) -> str:
    if curve.name == "secp256r1":
        return "P-256"
    return curve.name
