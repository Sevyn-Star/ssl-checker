import re
from datetime import timezone
from pathlib import Path

import pytest

from app.services.parser import parse_certificate, classify_type

FIXTURES = Path(__file__).parent / "fixtures"
_FINGERPRINT = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")


def _load(name: str):
    return parse_certificate((FIXTURES / name).read_text(encoding="utf-8"))


def test_leaf_ok_names_type_and_utc() -> None:
    cert = _load("leaf_ok.pem")
    assert cert.san_dns == ("example.com", "www.example.com")
    assert cert.san_ip == ()
    assert cert.subject_cn == "wrong.example"
    assert cert.certificate_type == "dv"
    assert cert.certificate_type_source == "policy"
    assert cert.not_before.tzinfo == timezone.utc
    assert cert.not_after.tzinfo == timezone.utc
    assert isinstance(cert.serial_hex, str)
    assert cert.public_key.algorithm == "RSA"
    assert cert.public_key.detail == "2048"


def test_intermediate_is_ca() -> None:
    assert _load("intermediate.pem").is_ca is True


def test_self_signed_subject_matches_issuer() -> None:
    cert = _load("leaf_self_signed.pem")
    assert cert.subject_dn == cert.issuer_dn
    assert cert.subject_cn == "self.example.com"


def test_ecdsa_public_key() -> None:
    cert = _load("leaf_ec.pem")
    assert cert.public_key.algorithm == "ECDSA"
    assert cert.public_key.detail == "P-256"
    assert cert.san_dns == ("ec.example.com",)


def test_fingerprint_shape_is_stable() -> None:
    first = _load("leaf_ok.pem")
    second = _load("leaf_ok.pem")
    assert _FINGERPRINT.fullmatch(first.fingerprint_sha256)
    assert first.fingerprint_sha256 == second.fingerprint_sha256
    assert first.serial_hex == second.serial_hex


def test_organization_without_policy_is_ov() -> None:
    cert = _load("leaf_ov_subject.pem")
    assert cert.subject_organization == "Example Org"
    assert cert.policy_oids == ()
    assert cert.certificate_type == "ov"
    assert cert.certificate_type_source == "subject"


def test_san_without_policy_or_organization_is_dv() -> None:
    cert = _load("leaf_san_ignores_cn.pem")
    assert cert.subject_cn == "other.example"
    assert cert.subject_organization is None
    assert cert.san_dns == ("www.example.com",)
    assert cert.policy_oids == ()
    assert cert.certificate_type == "dv"
    assert cert.certificate_type_source == "subject"


def test_wildcard_san() -> None:
    cert = _load("leaf_wildcard.pem")
    assert cert.san_dns == ("*.example.com",)


def test_garbage_pem_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_certificate("this is not a certificate")


@pytest.mark.parametrize(
    ("oids", "organization", "expected"),
    [
        (["2.23.140.1.2.1", "2.23.140.1.1"], None, ("ev", "policy")),
        (["2.23.140.1.2.1", "2.23.140.1.2.2"], "Example Org", ("ov", "policy")),
        (["2.23.140.1.2.1"], None, ("dv", "policy")),
        (["1.2.3.4"], "Example Org", ("ov", "subject")),
        ([], None, ("dv", "subject")),
        ([], "", ("dv", "subject")),
    ],
)
def test_classify_type(
    oids: list[str],
    organization: str | None,
    expected: tuple[str, str],
) -> None:
    assert classify_type(oids, organization) == expected


def test_fixtures_have_no_private_keys() -> None:
    pems = sorted(path.name for path in FIXTURES.glob("*.pem"))
    assert pems == [
        "intermediate.pem",
        "leaf_ec.pem",
        "leaf_ok.pem",
        "leaf_ov_subject.pem",
        "leaf_san_ignores_cn.pem",
        "leaf_self_signed.pem",
        "leaf_wildcard.pem",
    ]
    for path in FIXTURES.iterdir():
        if path.name == ".gitkeep":
            continue
        assert path.suffix == ".pem"
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in text
        assert "BEGIN CERTIFICATE" in text
