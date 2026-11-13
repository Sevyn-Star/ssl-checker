from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from app.services.chain import build_chain
from app.services.openssl_client import VerifyRaw
from app.services.parser import parse_certificate

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str):
    return parse_certificate((FIXTURES / name).read_text(encoding="utf-8"))


def test_unlinked_intermediate_stays_incomplete_when_verify_is_ok() -> None:
    leaf = _load("leaf_ok.pem")
    intermediate = _load("intermediate.pem")
    broken = replace(leaf, issuer_dn="CN=Not The Intermediate")
    now = leaf.not_before + timedelta(days=1)
    chain = build_chain(
        broken,
        [intermediate],
        VerifyRaw("complete", None, "ISRG Root X1"),
        now,
    )
    assert chain.status == "incomplete"
    assert chain.label == "不完整"
    assert chain.openssl_error is None
    assert chain.items[1].role == "intermediate"
    assert chain.items[1].role_label == "中间 CA 证书"
    assert chain.items[1].common_name == ""
    assert chain.items[1].status_label == "缺失"
    assert all(item.status_label != "可信" for item in chain.items)


def test_self_signed_verify_keeps_only_the_leaf() -> None:
    leaf = _load("leaf_ok.pem")
    intermediate = _load("intermediate.pem")
    assert leaf.issuer_dn == intermediate.subject_dn
    now = leaf.not_before + timedelta(days=1)
    chain = build_chain(
        leaf,
        [intermediate],
        VerifyRaw("self_signed", "error 18 at 0 depth lookup: self-signed certificate", None),
        now,
    )
    assert chain.status == "self_signed"
    assert chain.label == "不受信任"
    assert len(chain.items) == 1
    assert chain.items[0].role == "leaf"
    assert chain.openssl_error is not None
    assert chain.openssl_error.startswith("error 18")


def test_linked_chain_appends_a_trusted_root() -> None:
    leaf = _load("leaf_ok.pem")
    intermediate = _load("intermediate.pem")
    assert leaf.issuer_dn == intermediate.subject_dn
    now = leaf.not_before + timedelta(days=1)
    chain = build_chain(leaf, [intermediate], VerifyRaw("complete", None, "ISRG Root X1"), now)
    assert chain.status == "complete"
    assert chain.label == "完整"
    assert [item.role for item in chain.items] == ["leaf", "intermediate", "root"]
    assert chain.items[0].role_label == "服务器证书"
    assert chain.items[0].status_label == "有效"
    assert chain.items[0].common_name == "wrong.example"
    assert chain.items[1].role_label == "中间 CA 证书"
    assert chain.items[1].common_name == "Test Intermediate"
    assert chain.items[1].status_label == "有效"
    assert chain.items[2].role_label == "根 CA 证书"
    assert chain.items[2].common_name == "ISRG Root X1"
    assert chain.items[2].status == "trusted"
    assert chain.items[2].status_label == "可信"


def test_leaf_pill_follows_certificate_time() -> None:
    leaf = _load("leaf_ok.pem")
    intermediate = _load("intermediate.pem")
    verify = VerifyRaw("complete", None, "ISRG Root X1")
    expired = build_chain(leaf, [intermediate], verify, leaf.not_after)
    waiting = build_chain(leaf, [intermediate], verify, leaf.not_before - timedelta(seconds=1))
    assert expired.items[0].status_label == "已过期"
    assert waiting.items[0].status_label == "尚未生效"


def test_sent_root_is_not_drawn_twice() -> None:
    leaf = _load("leaf_ok.pem")
    sent_root = replace(
        _load("intermediate.pem"),
        subject_cn="ISRG Root X1",
        issuer_cn="ISRG Root X1",
        subject_dn="CN=ISRG Root X1",
        issuer_dn="CN=ISRG Root X1",
    )
    leaf = replace(leaf, issuer_dn="CN=ISRG Root X1")
    now = leaf.not_before + timedelta(days=1)
    chain = build_chain(leaf, [sent_root], VerifyRaw("complete", None, "ISRG Root X1"), now)
    assert [item.role for item in chain.items] == ["leaf", "root"]
    assert chain.items[1].status_label == "可信"


def test_missing_intermediate_adds_an_unfound_root() -> None:
    leaf = _load("leaf_ok.pem")
    now = leaf.not_before + timedelta(days=1)
    chain = build_chain(leaf, [], VerifyRaw("complete", None, None), now)
    assert chain.status == "incomplete"
    assert chain.items[0].role == "leaf"
    assert chain.items[1].role == "root"
    assert chain.items[1].common_name == ""
    assert chain.items[1].status_label == "未找到"
