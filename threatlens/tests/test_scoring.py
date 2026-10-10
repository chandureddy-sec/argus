"""Scoring model v1 (ADR 0008): the formula term by term, the configuration,
property tests (bounded scores, monotonic decay), and patch priority."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from threatlens.scoring.config import ScoringConfigError, load_config
from threatlens.scoring.model import Hit, Signal, decay, score
from threatlens.scoring.vulns import VulnFacts, patch_priority

CFG_PATH = Path(__file__).parent.parent / "config" / "scoring.yaml"
CFG = load_config(CFG_PATH)
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def sig(
    source: str = "feodo",
    upstream: str | None = None,
    grade: str = "B",
    kind: str = "malicious",
    conf: int = 85,
    age_days: float = 0,
    cred: int = 6,
    factor: float = 1.0,
) -> Signal:
    return Signal(
        source,
        upstream or source,
        grade,
        kind,
        conf,
        NOW - timedelta(days=age_days),
        cred,
        factor,  # type: ignore[arg-type]
    )


def run(*signals: Signal, obs: str = "ipv4-addr", **kw: object) -> tuple[float, str, dict[str, object]]:
    sc = score(signals, obs_type=obs, now=NOW, cfg=CFG, **kw)  # type: ignore[arg-type]
    return sc.priority, sc.verdict, sc.breakdown


# ── config ───────────────────────────────────────────────────────────────────


def test_config_loads_with_a_traceable_version() -> None:
    assert CFG.tag.startswith("1.0/")
    assert len(CFG.tag) == len("1.0/") + 8
    assert CFG.weight("A", 6) == 1.0
    assert CFG.weight("B", 3) == pytest.approx(0.85 * 0.9)
    assert CFG.half_life("url") == 7
    assert CFG.half_life("something-new") == 30  # default


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("verdict", "suspicious"), 70, "below verdict.malicious"),
        (("reliability_weights",), {"A": 1.0}, "A-F"),
        (("credibility_modifiers", 3), 1.5, "between 0 and 1"),
        (("half_life_days", "default"), 0, "positive"),
        (("patch_priority", "tiers"), {"P1": 10, "P2": 20, "P3": 5}, "P1 > P2 > P3"),
        (("unexpected",), 1, "Extra inputs"),
    ],
)
def test_bad_configs_are_rejected(
    tmp_path: Path, path: tuple[object, ...], value: object, message: str
) -> None:
    data = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8"))
    node = data
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = value
    bad = tmp_path / "scoring.yaml"
    bad.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ScoringConfigError, match=message):
        load_config(bad)


def test_missing_config_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ScoringConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


# ── the formula, term by term ────────────────────────────────────────────────


def test_base_is_confidence_times_weight_times_decay() -> None:
    p, v, bd = run(sig(conf=85))
    assert (p, v) == (72.25, "malicious")  # 85 x B 0.85
    assert bd["formula"] == "72.25 + 0 + 0 - 0 = 72.25"
    p, _, _ = run(sig(conf=85, age_days=10))  # one IP half-life
    assert p == pytest.approx(72.25 / 2, abs=0.01)
    p, _, _ = run(sig(conf=85, age_days=7), obs="url")  # one URL half-life
    assert p == pytest.approx(72.25 / 2, abs=0.01)
    assert run(sig(conf=85, cred=4))[0] == pytest.approx(85 * 0.85 * 0.75, abs=0.01)
    assert run(sig(conf=85, factor=0.5))[0] == pytest.approx(85 * 0.85 * 0.5, abs=0.01)


def test_corroboration_counts_independent_upstreams_only() -> None:
    urlhaus, threatfox = sig("urlhaus", "abuse.ch", conf=80), sig("threatfox", "abuse.ch", conf=75)
    assert run(urlhaus, threatfox)[2]["corroboration"] == {"value": 0, "upstreams": []}  # one upstream
    others = [sig(f"s{i}", f"u{i}", conf=60) for i in range(5)]
    p, _, bd = run(urlhaus, threatfox, *others)
    assert bd["corroboration"]["value"] == 24  # +8 each, capped at 24
    assert p == pytest.approx(68 + 24)
    weak = sig("otx", "otx", grade="C", conf=10)  # 7 < min_signal 15: doesn't count
    assert run(urlhaus, weak)[2]["corroboration"]["value"] == 0


def test_relevance_needs_a_real_report() -> None:
    hits = [Hit("own_asset", 20, "ours"), Hit("technique", 10, "T1566")]
    p, _, bd = run(sig(conf=60), relevance=hits)
    assert bd["relevance"] == {"value": 20, "applied": True, "hits": bd["relevance"]["hits"]}  # capped at 20
    assert p == pytest.approx(51 + 20)
    p, v, weak = run(sig(conf=10), relevance=hits)  # 8.5 < min_signal
    assert weak["relevance"]["applied"] is False
    assert (p, v) == (8.5, "unknown")
    assert run(relevance=hits)[:2] == (0, "unknown")


def test_penalties_and_benign_evidence() -> None:
    p, v, _ = run(sig(conf=85), sig("greynoise", kind="benign", conf=70, age_days=300))
    assert p == pytest.approx(72.25 - 70 * 0.85 * 0.5)  # benign evidence doesn't decay
    assert v == "suspicious"
    p, _, _ = run(sig(conf=85), penalties=[Hit("shared_cdn", 15, "cdn")])
    assert p == pytest.approx(57.25)
    assert run(sig("greynoise", kind="benign", conf=70))[1] == "benign"  # 29.75 >= benign_penalty
    assert run(sig(conf=10), penalties=[Hit("popular_domain", 10, "x")])[0] == 0  # never below 0


def test_suspicious_only_evidence_is_capped() -> None:
    many = [sig(f"s{i}", f"u{i}", kind="suspicious", conf=90) for i in range(4)]
    p, v, bd = run(*many)
    assert (p, v) == (59, "suspicious")
    assert "capped at 59" in bd["cap"]
    p, v, _ = run(*many, sig("feodo", conf=85))
    assert v == "malicious"
    assert p > 59


def test_suppression_wins() -> None:
    p, v, bd = run(sig(conf=100, grade="A"), suppressed="own domain")
    assert (p, v) == (0, "benign")
    assert bd["formula"] == "suppressed: own domain"


def test_valid_until_is_when_the_strongest_report_decays_below_expiry() -> None:
    s = score([sig(conf=80, grade="A")], obs_type="ipv4-addr", now=NOW, cfg=CFG)
    # 80 -> 10 is three halvings: 3 x 10 days
    assert s.valid_until == NOW + timedelta(days=30)
    later = score([sig(conf=80, grade="A")], obs_type="ipv4-addr", now=NOW + timedelta(days=31), cfg=CFG)
    assert later.priority < CFG.expiry.below
    assert score([], obs_type="ipv4-addr", now=NOW, cfg=CFG).valid_until is None


def test_breakdown_is_complete_and_reproducible() -> None:
    _, _, bd = run(sig("feodo", "abuse.ch", conf=85), sig("abuseipdb", grade="C", conf=90))
    assert set(bd) >= {"model", "config", "computed_at", "base", "corroboration", "relevance", "penalty",
                       "formula", "priority", "verdict", "signals", "thresholds"}  # fmt: skip
    assert bd["model"] == "v1"
    assert [s["source"] for s in bd["signals"]] == ["feodo", "abuseipdb"]  # strongest first
    total = (
        bd["base"]["value"] + bd["corroboration"]["value"] + bd["relevance"]["value"] - bd["penalty"]["value"]
    )
    assert bd["priority"] == pytest.approx(max(0, min(100, total)), abs=0.01)


# ── properties ───────────────────────────────────────────────────────────────

signals_st = st.lists(
    st.builds(
        sig,
        source=st.sampled_from(["feodo", "urlhaus", "otx", "abuseipdb", "greynoise", "vt"]),
        upstream=st.sampled_from(["abuse.ch", "otx", "abuseipdb", "greynoise", "vt"]),
        grade=st.sampled_from(list("ABCDEF")),
        kind=st.sampled_from(["malicious", "suspicious", "benign"]),
        conf=st.integers(-50, 250),  # out-of-range input is clamped
        age_days=st.floats(0, 3650),
        cred=st.integers(1, 6),
        factor=st.floats(0, 2),
    ),
    max_size=8,
)
hits_st = st.lists(st.builds(Hit, st.sampled_from(["a", "b"]), st.floats(0, 100), st.just("r")), max_size=4)
obs_st = st.sampled_from(["ipv4-addr", "url", "domain-name", "sha256", "file-name", "weird"])


@settings(max_examples=300)
@given(signals_st, hits_st, hits_st, obs_st)
def test_score_is_always_bounded(signals: list[Signal], rel: list[Hit], pen: list[Hit], obs: str) -> None:
    s = score(signals, obs_type=obs, now=NOW, cfg=CFG, relevance=rel, penalties=pen)
    assert 0 <= s.priority <= 100
    assert s.verdict in ("malicious", "suspicious", "benign", "unknown")
    if s.verdict == "malicious":
        assert s.priority >= CFG.verdict.malicious


@settings(max_examples=300)
@given(signals_st, hits_st, hits_st, obs_st, st.floats(0, 400), st.floats(0, 400))
def test_score_never_rises_with_time(
    signals: list[Signal], rel: list[Hit], pen: list[Hit], obs: str, d1: float, d2: float
) -> None:
    early, late = sorted((d1, d2))
    a = score(signals, obs_type=obs, now=NOW + timedelta(days=early), cfg=CFG, relevance=rel, penalties=pen)
    b = score(signals, obs_type=obs, now=NOW + timedelta(days=late), cfg=CFG, relevance=rel, penalties=pen)
    assert b.priority <= a.priority + 1e-9


@settings(max_examples=300)
@given(
    signals_st, hits_st, hits_st, obs_st, st.integers(0, 100), st.sampled_from(["malicious", "suspicious"])
)
def test_a_new_independent_report_never_lowers_the_score(
    signals: list[Signal], rel: list[Hit], pen: list[Hit], obs: str, conf: int, kind: str
) -> None:
    before = score(signals, obs_type=obs, now=NOW, cfg=CFG, relevance=rel, penalties=pen)
    extra = sig("new-feed", "new-upstream", grade="B", kind=kind, conf=conf)
    after = score([*signals, extra], obs_type=obs, now=NOW, cfg=CFG, relevance=rel, penalties=pen)
    assert after.priority >= before.priority - 1e-9


@given(st.floats(0, 10_000), st.floats(0, 10_000), st.floats(0.1, 1000))
def test_decay_is_monotonic_and_bounded(a: float, b: float, half: float) -> None:
    lo, hi = sorted((a, b))
    assert 0 <= decay(hi, half) <= decay(lo, half) <= 1
    assert decay(0, half) == 1


# ── patch priority ───────────────────────────────────────────────────────────


def pp(facts: VulnFacts, stack: tuple[str, ...] = (), exposed: tuple[str, ...] = ()) -> dict[str, object]:
    return patch_priority(facts, in_stack=list(stack), exposed=list(exposed), cfg=CFG)


def test_kev_is_a_floor() -> None:
    low = pp(VulnFacts("CVE-1", kev=True, cvss_score=3.0))
    assert (low["priority"], low["floor"]) == ("P2", "KEV entry: at least P2")
    ours = pp(VulnFacts("CVE-1", kev=True, cvss_score=3.0), stack=("apache:http_server",))
    assert ours["priority"] == "P1"
    assert "affecting our stack" in str(ours["floor"])


def test_points_and_tiers() -> None:
    assert pp(VulnFacts("CVE-2"))["priority"] == "P4"
    hot = pp(VulnFacts("CVE-3", epss_percentile=0.97, cvss_score=9.8, exploitation="poc"))
    assert hot["score"] == 25 + 20 + 15
    assert hot["priority"] == "P2"
    exposed = pp(
        VulnFacts("CVE-4", exploitation="active", cvss_score=7.5),
        stack=("fortinet:fortios",),
        exposed=("fortinet:fortios",),
    )
    assert exposed["score"] == 30 + 10 + 25 + 15
    assert exposed["priority"] == "P1"
    reasons = [r["reason"] for r in exposed["reasons"]]  # type: ignore[attr-defined]
    assert any("internet-facing" in r for r in reasons)
    assert pp(VulnFacts("CVE-5", cvss_score=5.0, epss_percentile=0.6))["priority"] == "P4"


@given(
    st.booleans(),
    st.sampled_from([None, "Known", "Unknown"]),
    st.sampled_from([None, "none", "poc", "active"]),
    st.integers(0, 5),
    st.one_of(st.none(), st.floats(0, 1)),
    st.one_of(st.none(), st.floats(0, 10)),
    st.booleans(),
    st.booleans(),
)
def test_patch_priority_is_total_and_kev_never_below_p2(
    kev: bool,
    ransom: str | None,
    expl: str | None,
    refs: int,
    epss: float | None,
    cvss: float | None,
    in_stack: bool,
    exposed: bool,
) -> None:
    r = pp(
        VulnFacts("CVE-X", kev, ransom, expl, refs, epss, cvss),
        stack=("v:p",) if in_stack else (),
        exposed=("v:p",) if exposed else (),
    )
    assert r["priority"] in ("P1", "P2", "P3", "P4")
    if kev:
        assert r["priority"] in ("P1", "P2")
    if kev and in_stack:
        assert r["priority"] == "P1"
