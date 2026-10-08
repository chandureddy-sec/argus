from __future__ import annotations

import contextlib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from threatlens.profile import (
    OrgProfile,
    PIRSet,
    ProfileError,
    cross_check,
    load_pirs,
    load_profile,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PROFILE = ROOT / "config" / "org_profile.yaml"
EXAMPLE_PIRS = ROOT / "config" / "pirs.yaml"


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_example_files_are_valid() -> None:
    profile = load_profile(EXAMPLE_PROFILE)
    pirs = load_pirs(EXAMPLE_PIRS, profile)
    assert profile.org.domains == ["example.com", "example.in"]
    assert profile.org.ip_ranges == ["203.0.113.0/24"]
    assert [p.id for p in pirs.pirs] == ["PIR-1", "PIR-2", "PIR-3"]
    # `match: tech_stack` (a bare string) is normalised to a list.
    assert pirs.pirs[1].watch.match == ["tech_stack"]


def org(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"name": "Acme", "domains": ["acme.com"]}
    base.update(over)
    return {"org": base}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("domains", ["not a domain"], "not a valid domain"),
        ("domains", ["-bad.com"], "not a valid domain"),
        ("ip_ranges", ["203.0.113.5/24"], "not a valid CIDR"),  # host bits set
        ("ip_ranges", ["999.1.1.0/24"], "not a valid CIDR"),
        ("geography", ["India"], "String should match pattern"),
        ("sectors", ["Fin Tech"], "String should match pattern"),
        ("tech_stack", [{"product": "X", "cpe": "apache:tomcat"}], "not a CPE 2.3"),
    ],
)
def test_profile_rejects_bad_values(field: str, value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        OrgProfile.model_validate(org(**{field: value}))


def test_profile_normalises_values() -> None:
    p = OrgProfile.model_validate(
        org(
            domains=["Example.COM."],
            ip_ranges=[" 2001:db8::/32 "],
            tech_stack=[{"product": "T", "cpe": "CPE:2.3:A:Apache:Tomcat:*"}],
        )
    )
    assert p.org.domains == ["example.com"]
    assert p.org.ip_ranges == ["2001:db8::/32"]
    assert p.org.tech_stack[0].cpe == "cpe:2.3:a:apache:tomcat:*"


def test_unknown_fields_are_rejected() -> None:
    # A typo like `domain:` must fail rather than silently leave domains empty.
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        OrgProfile.model_validate({"org": {"name": "Acme", "domain": ["acme.com"]}})


def pirs(*items: dict[str, object]) -> dict[str, object]:
    return {"pirs": list(items)}


def test_pirs_validation() -> None:
    ok = {"id": "PIR-1", "question": "Who is phishing our brand?", "watch": {"match": ["brands"]}}
    with pytest.raises(ValueError, match="duplicate PIR id"):
        PIRSet.model_validate(pirs(ok, ok))
    with pytest.raises(ValueError, match="at least one of"):
        PIRSet.model_validate(pirs({**ok, "watch": {}}))
    with pytest.raises(ValueError, match="String should match pattern"):
        PIRSet.model_validate(pirs({**ok, "watch": {"techniques": ["T15"]}}))
    with pytest.raises(ValueError, match="Input should be"):
        PIRSet.model_validate(pirs({**ok, "watch": {"match": ["emails"]}}))
    with pytest.raises(ValueError, match="at least 1 item"):
        PIRSet.model_validate({"pirs": []})
    sub = PIRSet.model_validate(pirs({**ok, "watch": {"techniques": ["T1566.001"]}}))
    assert sub.pirs[0].watch.techniques == ["T1566.001"]


def test_cross_check_flags_pirs_that_can_never_match() -> None:
    profile = OrgProfile.model_validate(org(sectors=["fintech"], geography=["IN"]))
    p = PIRSet.model_validate(
        pirs(
            {
                "id": "PIR-1",
                "question": "Which actors target healthcare in the US?",
                "watch": {"sectors": ["healthcare"], "geography": ["US"], "match": ["tech_stack"]},
            }
        )
    )
    problems = cross_check(profile, p)
    assert len(problems) == 3
    assert any("healthcare" in x for x in problems)
    assert any("org.tech_stack is empty" in x for x in problems)


def test_load_errors_are_profile_errors(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="cannot read"):
        load_profile(tmp_path / "missing.yaml")
    with pytest.raises(ProfileError, match="not valid YAML"):
        load_profile(write(tmp_path, "bad.yaml", "org: [unclosed"))
    with pytest.raises(ProfileError, match="not a valid domain"):
        load_profile(write(tmp_path, "p.yaml", "org: {name: A, domains: ['x y']}"))
    good = write(tmp_path, "good.yaml", "org: {name: A, sectors: [fintech]}")
    bad_pirs = write(
        tmp_path,
        "pirs.yaml",
        "pirs: [{id: PIR-1, question: 'Who targets healthcare?', watch: {sectors: [healthcare]}}]",
    )
    with pytest.raises(ProfileError, match="healthcare"):
        load_pirs(bad_pirs, load_profile(good))


def test_yaml_object_tags_are_not_executed(tmp_path: Path) -> None:
    # safe_load must refuse to construct Python objects from YAML tags.
    evil = write(tmp_path, "evil.yaml", "org: !!python/object/apply:os.system ['echo pwned']")
    with pytest.raises(ProfileError, match="not valid YAML"):
        load_profile(evil)


@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.text(max_size=300))
def test_any_text_either_loads_or_raises_profile_error(tmp_path: Path, text: str) -> None:
    # Property: arbitrary file content never crashes the loader with another exception type.
    p = tmp_path / "fuzz.yaml"
    p.write_text(text, encoding="utf-8", errors="surrogatepass")
    with contextlib.suppress(ProfileError):
        load_profile(p)
