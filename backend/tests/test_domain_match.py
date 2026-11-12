from pathlib import Path

import pytest

from app.services.domain_match import DomainMatch, match_hostname

_PUNYCODE = "xn--fsqu00a.xn--0zwm56d"


@pytest.mark.parametrize(
    ("host", "cn", "san_dns", "san_ip", "expected"),
    [
        (
            "www.example.com",
            None,
            ["www.example.com"],
            [],
            DomainMatch(True, "www.example.com", "san", None, ("www.example.com",), (), False),
        ),
        (
            "example.com",
            None,
            ["www.example.com"],
            [],
            DomainMatch(False, None, None, None, ("www.example.com",), (), False),
        ),
        (
            "a.example.com",
            None,
            ["*.example.com"],
            [],
            DomainMatch(True, "*.example.com", "san", None, ("*.example.com",), (), True),
        ),
        (
            "example.com",
            None,
            ["*.example.com"],
            [],
            DomainMatch(False, None, None, None, ("*.example.com",), (), True),
        ),
        (
            "a.b.example.com",
            None,
            ["*.example.com"],
            [],
            DomainMatch(False, None, None, None, ("*.example.com",), (), True),
        ),
        (
            "www.a.example.com",
            None,
            ["www.*.example.com"],
            [],
            DomainMatch(False, None, None, None, ("www.*.example.com",), (), False),
        ),
        (
            "www.example.com",
            "other.example.com",
            ["www.example.com"],
            [],
            DomainMatch(
                True,
                "www.example.com",
                "san",
                "other.example.com",
                ("www.example.com",),
                (),
                False,
            ),
        ),
        (
            "www.example.com",
            "www.example.com",
            ["other.example.com"],
            [],
            DomainMatch(False, None, None, "www.example.com", ("other.example.com",), (), False),
        ),
        (
            "www.example.com",
            "www.example.com",
            [],
            [],
            DomainMatch(True, "www.example.com", "cn", "www.example.com", (), (), False),
        ),
        (
            "203.0.113.10",
            "other.example.com",
            [],
            ["203.0.113.10"],
            DomainMatch(True, "203.0.113.10", "san", "other.example.com", (), ("203.0.113.10",), False),
        ),
        (
            "203.0.113.10",
            "203.0.113.10",
            ["www.example.com"],
            [],
            DomainMatch(False, None, None, "203.0.113.10", ("www.example.com",), (), False),
        ),
    ],
)
def test_planning_table(
    host: str,
    cn: str | None,
    san_dns: list[str],
    san_ip: list[str],
    expected: DomainMatch,
) -> None:
    assert match_hostname(host, cn=cn, san_dns=san_dns, san_ip=san_ip) == expected


def test_comparison_is_case_insensitive() -> None:
    got = match_hostname("www.example.com", cn=None, san_dns=["WWW.Example.com"], san_ip=[])
    assert got.matched is True
    assert got.source == "san"
    assert got.matched_name == "www.example.com"
    assert got.san_dns == ("www.example.com",)


def test_trailing_dot_is_removed_before_comparison() -> None:
    got = match_hostname("www.example.com", cn=None, san_dns=["www.example.com."], san_ip=[])
    assert got.matched is True
    assert got.source == "san"
    assert got.san_dns == ("www.example.com",)


def test_second_san_is_used_when_the_first_misses() -> None:
    got = match_hostname(
        "www.example.com",
        cn=None,
        san_dns=["mail.example.com", "www.example.com"],
        san_ip=[],
    )
    assert got.matched is True
    assert got.matched_name == "www.example.com"
    assert got.source == "san"


def test_exact_san_matches_while_another_name_keeps_wildcard_flag() -> None:
    got = match_hostname(
        "www.example.com",
        cn=None,
        san_dns=["www.example.com", "*.example.com"],
        san_ip=[],
    )
    assert got == DomainMatch(
        True,
        "www.example.com",
        "san",
        None,
        ("www.example.com", "*.example.com"),
        (),
        True,
    )


def test_first_matching_certificate_name_wins() -> None:
    got = match_hostname(
        "www.example.com",
        cn=None,
        san_dns=["*.example.com", "www.example.com"],
        san_ip=[],
    )
    assert got.matched_name == "*.example.com"
    assert got.source == "san"
    assert got.wildcard is True


def test_wildcard_input_is_not_a_hostname() -> None:
    got = match_hostname("*.example.com", cn=None, san_dns=["*.example.com"], san_ip=[])
    assert got.matched is False
    assert got.source is None
    assert got.matched_name is None
    assert got.wildcard is True


def test_unicode_input_matches_punycode_certificate_name() -> None:
    got = match_hostname("例子.测试", cn=None, san_dns=[_PUNYCODE], san_ip=[])
    assert got.matched is True
    assert got.source == "san"
    assert got.matched_name == _PUNYCODE


def test_empty_names_do_not_match() -> None:
    got = match_hostname("www.example.com", cn=None, san_dns=[], san_ip=[])
    assert got == DomainMatch(False, None, None, None, (), (), False)


def test_cn_matches_only_when_san_is_absent() -> None:
    got = match_hostname("www.example.com", cn="WWW.Example.com.", san_dns=None, san_ip=None)
    assert got.matched is True
    assert got.source == "cn"
    assert got.matched_name == "www.example.com"
    assert got.cn == "www.example.com"


def test_ip_san_blocks_cn_for_a_domain() -> None:
    got = match_hostname(
        "www.example.com",
        cn="www.example.com",
        san_dns=[],
        san_ip=["203.0.113.10"],
    )
    assert got.matched is False
    assert got.source is None


def test_ip_is_not_compared_with_a_dns_name_of_the_same_text() -> None:
    got = match_hostname(
        "203.0.113.10",
        cn=None,
        san_dns=["203.0.113.10"],
        san_ip=[],
    )
    assert got.matched is False
    assert got.source is None


def test_public_suffix_is_not_special() -> None:
    """V1 不引入公共后缀表，*.com 按普通通配符匹配 a.com。"""
    matched = match_hostname("a.com", cn=None, san_dns=["*.com"], san_ip=[])
    assert matched.matched is True
    assert matched.matched_name == "*.com"
    assert matched.source == "san"
    assert matched.wildcard is True
    assert match_hostname("com", cn=None, san_dns=["*.com"], san_ip=[]).matched is False
    assert match_hostname("a.b.com", cn=None, san_dns=["*.com"], san_ip=[]).matched is False


def test_one_bad_name_does_not_fail_the_rest() -> None:
    got = match_hostname(
        "www.example.com",
        cn="a..b",
        san_dns=["a..b", "www.example.com"],
        san_ip=[],
    )
    assert got.matched is True
    assert got.matched_name == "www.example.com"
    assert got.source == "san"
    assert got.cn is None
    assert got.san_dns == ("www.example.com",)


def test_bad_input_does_not_raise() -> None:
    got = match_hostname("a..b", cn="www.example.com", san_dns=[], san_ip=[])
    assert got.matched is False
    assert got.source is None


def test_module_does_not_call_host_validation() -> None:
    source = Path(match_hostname.__code__.co_filename).read_text(encoding="utf-8")
    assert "normalize_host" not in source
    assert "app.security" not in source
