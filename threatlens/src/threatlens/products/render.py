"""Rendering products as HTML and PDF from the same structure (ADR 0021).

HTML is a self-contained page (inline CSS, no scripts, autoescaped) with the
TLP marking at the top and bottom and every citation linked to its Argus
record. PDF uses ``threatlens.pdf`` (marking on every page).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from threatlens import pdf

_ENV = Environment(autoescape=select_autoescape(default=True, default_for_string=True))  # nosec B701

_HTML = _ENV.from_string((Path(__file__).with_name("product.html")).read_text(encoding="utf-8"))


def html(product: dict[str, Any], base_url: str) -> str:
    color = {
        "TLP:CLEAR": "#3c3c3c",
        "TLP:GREEN": "#33a02c",
        "TLP:AMBER": "#cc8800",
        "TLP:AMBER+STRICT": "#cc8800",
    }.get(product["tlp"], "#cc0033")
    return _HTML.render(p=product, base=base_url.rstrip("/") + "/app", color=color)


def _cite(refs: list[str]) -> str:
    return f" [{', '.join(refs)}]" if refs else ""


def blocks(product: dict[str, Any]) -> list[pdf.Block]:
    b = product["body"]
    out: list[pdf.Block] = [
        pdf.h1(product["title"]),
        pdf.small(f"{product['org']} · {product['period']['start']} to {product['period']['end']}"),
    ]
    kind = product["kind"]
    if kind in ("daily", "weekly"):
        prev = f" (previous week {b['previous']['indicators']})" if b.get("previous") else ""
        out += [
            pdf.kv(
                [
                    (
                        "New indicators",
                        f"{b['indicators']['total']}{prev}; {b['indicators']['high']} high priority",
                    ),
                    ("Newly exploited", f"{b['kev']['added']} CVEs, {b['kev']['inStack']} in our stack"),
                    ("Cases", f"{b['cases']['opened']} opened, {b['cases']['closed']} closed"),
                    ("Alerts", str(b["alerts"])),
                ]
            ),
            pdf.h2("Highest-priority new indicators"),
            pdf.table(
                ["Indicator", "Score", "Labels", "Sources", "Record"],
                [
                    [
                        t["value"],
                        str(t["score"]),
                        ", ".join(t["labels"]),
                        ", ".join(t["sources"]) or "analyst",
                        t["ref"],
                    ]
                    for t in b["indicators"]["top"]
                ],
                [34, 8, 22, 18, 18],
            ),
            pdf.h2("Malware families behind new indicators"),
            pdf.bullets(
                [f"{f['name']} ({f['ref']}): {f['indicators']} indicator(s)" for f in b["families"]]
                or ["None linked."]
            ),
            pdf.h2("Newly exploited vulnerabilities (CISA KEV)"),
            pdf.table(
                ["CVE", "Name", "Due", "Priority", "Our stack"],
                [
                    [k["ref"], k["name"], k["due"] or "", k["priority"] or "", "yes" if k["inStack"] else ""]
                    for k in b["kev"]["items"]
                ],
                [18, 42, 14, 12, 14],
            ),
            pdf.h2("Investigations"),
            pdf.bullets(
                [f"{c['ref']}: {c['title']} ({c['severity']}, {c['status']})" for c in b["cases"]["items"]]
                or ["No cases opened."]
            ),
        ]
        look = b.get("lookalikes") or {}
        if look.get("items"):
            out += [
                pdf.h2("Lookalike domains"),
                pdf.table(
                    ["Domain", "Imitates", "Technique", "Seen in", "Record"],
                    [
                        [
                            lk["candidate"],
                            lk["imitates"],
                            lk["technique"],
                            ", ".join(lk["sources"]),
                            lk["ref"],
                        ]
                        for lk in look["items"]
                    ],
                    [30, 22, 16, 14, 18],
                ),
            ]
        if b["feeds"]:
            out += [
                pdf.h2("Collection problems"),
                pdf.bullets([f"{f['ref']}: {f['failed']} of {f['runs']} pulls failed" for f in b["feeds"]]),
            ]
    elif kind == "vulns":
        out += [
            pdf.p("Vulnerabilities to patch first: P1 and P2, those in our software on top."),
            pdf.table(
                ["CVE", "Priority", "Why", "Our stack", "Due"],
                [
                    [
                        f"{v['ref']} {v['name'][:60]}",
                        f"{v['priority']} ({v['score']})",
                        "; ".join(v["why"]),
                        "yes" if v["inStack"] else "",
                        v["due"] or "",
                    ]
                    for v in b["items"]
                ],
                [28, 12, 38, 10, 12],
            ),
        ]
    else:
        out += [
            pdf.kv(
                [
                    ("High-priority threats", str(b["indicators"]["high"])),
                    ("Exploited flaws in our software", str(b["kev"]["inStack"])),
                    ("Investigations opened", str(b["cases"]["opened"])),
                    ("Alerts", str(b["alerts"])),
                ]
            ),
            pdf.h2("What matters this week"),
            pdf.bullets([f"{r['risk']} {r['action']}{_cite(r['refs'])}" for r in b["risks"]]),
        ]
    out += [
        pdf.rule(),
        pdf.small(f"Generated by Argus from stored records. Fingerprint {product['sha256'][:16]}."),
    ]
    return out


def to_pdf(product: dict[str, Any]) -> bytes:
    return pdf.render(
        f"{product['title']} · {product['period']['end']}", blocks(product), marking=product["tlp"]
    )
