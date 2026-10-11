"""Server-rendered SVG charts.

No JavaScript and no third-party chart library: each chart is a small SVG
string built here, so pages work under a strict Content-Security-Policy
(``script-src 'none'``). Every piece of text placed in the SVG is escaped,
and tooltips are native SVG ``<title>`` elements.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from markupsafe import Markup, escape

Point = tuple[float, float]


def _svg(markup: str) -> Markup:
    """Mark built SVG/HTML as safe. Every value interpolated into it is a
    number formatted here or text passed through ``escape()``."""
    return Markup(markup)  # noqa: S704  # nosec B704 - see docstring


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return float(m * exp)
    return float(10 * exp)


def _fmt(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M".replace(".0M", "M")
    if v >= 1000:
        return f"{v / 1000:.1f}k".replace(".0k", "k")
    return f"{v:g}"


def _smooth(points: Sequence[Point], top: float, bottom: float) -> str:
    """Catmull-Rom spline through the points as cubic Béziers, with control
    points clamped to the plot so the curve never dips below zero."""
    if not points:
        return ""
    d = [f"M{points[0][0]:.1f},{points[0][1]:.1f}"]
    for i in range(len(points) - 1):
        p0 = points[i - 1] if i else points[i]
        p1, p2 = points[i], points[i + 1]
        p3 = points[i + 2] if i + 2 < len(points) else p2
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, min(bottom, max(top, p1[1] + (p2[1] - p0[1]) / 6)))
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, min(bottom, max(top, p2[1] - (p3[1] - p1[1]) / 6)))
        d.append(f"C{c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}")
    return " ".join(d)


def area_chart(
    series: Sequence[tuple[str, float]],
    *,
    color: str,
    unit: str = "",
    width: int = 420,
    height: int = 170,
    xlabels: int = 4,
    markers: int = 0,
    fill: str | None = None,
) -> Markup:
    """A smooth line with a soft fill. ``series`` is [(label, value)];
    ``markers`` labels that many peaks with a drop line and value."""
    left, right, top, bottom = 34, 8, 10, height - 22
    if not series:
        return _svg(f'<svg class="chart" viewBox="0 0 {width} {height}" role="img"></svg>')
    vmax = _nice_max(max(v for _, v in series))
    plot_w = width - left - right
    n = len(series)
    step = plot_w / max(1, n - 1)
    pts = [(left + i * step, bottom - (v / vmax) * (bottom - top)) for i, (_, v) in enumerate(series)]
    gid = f"g{abs(hash((color, n, vmax))) % 10_000_000}"
    out = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" preserveAspectRatio="none">',
        f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{fill or color}" stop-opacity="0.38"/>'
        f'<stop offset="1" stop-color="{fill or color}" stop-opacity="0"/></linearGradient></defs>',
    ]
    for k in range(5):
        v = vmax * k / 4
        y = bottom - (v / vmax) * (bottom - top)
        out.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text class="tick" x="{left - 6}" y="{y + 3:.1f}" text-anchor="end">{_fmt(v)}</text>')
    if n > 1:
        for k in range(xlabels):
            i = round(k * (n - 1) / max(1, xlabels - 1))
            out.append(
                f'<text class="tick" x="{left + i * step:.1f}" y="{height - 6}" '
                f'text-anchor="{"start" if k == 0 else "end" if k == xlabels - 1 else "middle"}">'
                f"{escape(series[i][0])}</text>"
            )
    line = _smooth(pts, top, bottom)
    out.append(
        f'<path d="{line} L{pts[-1][0]:.1f},{bottom} L{pts[0][0]:.1f},{bottom} Z" fill="url(#{gid})"/>'
    )
    out.append(f'<path class="line" d="{line}" stroke="{color}"/>')
    peaks = sorted(range(n), key=lambda i: series[i][1], reverse=True)[:markers] if markers else []
    for i in sorted(peaks):
        if series[i][1] <= 0:
            continue
        x, y = pts[i]
        anchor = "start" if x < width * 0.75 else "end"
        dx = 6 if anchor == "start" else -6
        out.append(
            f'<line class="mark-line" x1="{x:.1f}" x2="{x:.1f}" y1="{y:.1f}" y2="{bottom}"/>'
            f'<circle class="marker" cx="{x:.1f}" cy="{y:.1f}" r="3.2"/>'
            f'<text class="mark-label" x="{x + dx:.1f}" y="{max(top + 9, y - 6):.1f}" text-anchor="{anchor}">'
            f"{escape(series[i][0])} · {_fmt(series[i][1])}</text>"
        )
    for (label, v), (x, y) in zip(series, pts, strict=True):
        out.append(
            f'<circle class="hit" cx="{x:.1f}" cy="{y:.1f}" r="{max(3.0, step / 2):.1f}">'
            f"<title>{escape(label)}: {_fmt(v)}{escape(unit)}</title></circle>"
        )
    out.append("</svg>")
    return _svg("".join(out))


def bar_list(rows: Sequence[tuple[str, float, str | None]], *, color: str, unit: str = "") -> Markup:
    """Horizontal bars (label, value, optional link). Each bar is a tiny SVG,
    so widths need no inline ``style`` attribute (blocked by the CSP)."""
    if not rows:
        return _svg('<p class="empty">No data yet.</p>')
    vmax = max(v for _, v, _ in rows) or 1
    out = ['<ul class="bars">']
    for label, v, href in rows:
        pct = 100 * v / vmax
        name = f'<a href="{escape(href)}">{escape(label)}</a>' if href else str(escape(label))
        out.append(
            f'<li><span class="bar-label">{name}</span>'
            f'<svg class="bar" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">'
            f'<rect x="0" y="0" width="100" height="6" rx="3" class="bar-bg"/>'
            f'<rect x="0" y="0" width="{pct:.1f}" height="6" rx="3" fill="{color}"/></svg>'
            f'<span class="bar-value">{_fmt(v)}{escape(unit)}</span></li>'
        )
    out.append("</ul>")
    return _svg("".join(out))


def histogram(
    bins: Sequence[tuple[str, float]], *, color: str, width: int = 420, height: int = 170
) -> Markup:
    left, right, top, bottom = 34, 8, 10, height - 22
    if not bins:
        return _svg("")
    vmax = _nice_max(max(v for _, v in bins))
    bw = (width - left - right) / len(bins)
    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" preserveAspectRatio="none">']
    for k in range(5):
        v = vmax * k / 4
        y = bottom - (v / vmax) * (bottom - top)
        out.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text class="tick" x="{left - 6}" y="{y + 3:.1f}" text-anchor="end">{_fmt(v)}</text>')
    for i, (label, v) in enumerate(bins):
        h = (v / vmax) * (bottom - top)
        x = left + i * bw
        out.append(
            f'<rect x="{x + 2:.1f}" y="{bottom - h:.1f}" width="{bw - 4:.1f}" height="{h:.1f}" '
            f'rx="2" fill="{color}"><title>{escape(label)}: {_fmt(v)}</title></rect>'
        )
        if i % 2 == 0:
            out.append(
                f'<text class="tick" x="{x + bw / 2:.1f}" y="{height - 6}" '
                f'text-anchor="middle">{escape(label)}</text>'
            )
    out.append("</svg>")
    return _svg("".join(out))


@lru_cache(maxsize=1)
def _world() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((Path(__file__).parent / "worldmap.json").read_text(encoding="utf-8"))
    return data


def _project(lon: float, lat: float, w: float, h: float) -> Point:
    m = _world()
    return (lon + 180) / 360 * w, (m["lat_max"] - lat) / (m["lat_max"] - m["lat_min"]) * h


def world_map(points: dict[str, int], *, width: int = 720, height: int = 300) -> Markup:
    """Dotted world map; ``points`` maps ISO country codes to counts."""
    m = _world()
    out = [f'<svg class="map" viewBox="0 0 {width} {height}" role="img">']
    dot = width / (360 / m["step"]) * 0.32
    for lon, lat in m["dots"]:
        x, y = _project(lon, lat, width, height)
        out.append(f'<circle class="land" cx="{x:.1f}" cy="{y:.1f}" r="{dot:.2f}"/>')
    peak = max(points.values(), default=1)
    for iso, n in sorted(points.items(), key=lambda kv: kv[1]):
        c = m["countries"].get(iso.upper())
        if not c:
            continue
        x, y = _project(c[0], c[1], width, height)
        rad = 3 + 6 * math.sqrt(n / peak)
        level = "crit" if n / peak > 0.66 else "high" if n / peak > 0.33 else "med"
        out.append(
            f'<g class="hot {level}"><circle class="halo" cx="{x:.1f}" cy="{y:.1f}" r="{rad * 2:.1f}"/>'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rad:.1f}">'
            f"<title>{escape(c[2])}: {n}</title></circle></g>"
        )
    out.append("</svg>")
    return _svg("".join(out))


# ── neon gauges (ADR 0009) ───────────────────────────────────────────────────

PALETTES: dict[str, tuple[str, ...]] = {
    "neon": ("#ff4fa3", "#8b5cf6", "#2ee6f0"),
    "hot": ("#ff4f7b", "#ff9f45", "#ffd84d"),
    "pink": ("#ff4f7b", "#ff4fa3", "#b06cff"),
    "cool": ("#2ee6f0", "#5b8cff", "#8b5cf6"),
    "lime": ("#b5f23d", "#2ee6f0"),
    "amber": ("#ffc53d", "#ff9f45"),
}
DIM = "#2a1f47"


def _hex(c: str) -> tuple[int, int, int]:
    return int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16)


def blend(palette: str, t: float) -> str:
    """Colour at ``t`` (0..1) along a palette's stops."""
    stops = PALETTES.get(palette, PALETTES["neon"])
    t = min(1.0, max(0.0, t))
    if len(stops) == 1:
        return stops[0]
    pos = t * (len(stops) - 1)
    i = min(int(pos), len(stops) - 2)
    f = pos - i
    a, b = _hex(stops[i]), _hex(stops[i + 1])
    r, g, bl = (round(a[k] + (b[k] - a[k]) * f) for k in range(3))
    return f"#{r:02x}{g:02x}{bl:02x}"


def ring_gauge(
    pct: float, value: str, *, palette: str = "neon", caption: str = "", segments: int = 44
) -> Markup:
    """A segmented ring: ``pct`` (0-100) of the segments lit along the palette,
    ``value`` in the middle and ``caption`` (e.g. "62%") under it."""
    pct = min(100.0, max(0.0, pct))
    lit = round(segments * pct / 100)
    cx = cy = 60
    r1, r2 = 41, 53
    out = [
        f'<svg class="gauge" viewBox="0 0 120 120" role="img" '
        f'aria-label="{escape(value)} ({escape(caption)})">'
    ]
    for i in range(segments):
        a = math.radians(-90 + (i + 0.5) * 360 / segments)
        x1, y1 = cx + r1 * math.cos(a), cy + r1 * math.sin(a)
        x2, y2 = cx + r2 * math.cos(a), cy + r2 * math.sin(a)
        color = blend(palette, i / max(1, segments - 1)) if i < lit else DIM
        out.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" '
            f'stroke-width="4.2" stroke-linecap="round"/>'
        )
    out.append(
        f'<text class="val" x="60" y="{64 if not caption else 61}" text-anchor="middle">'
        f"{escape(value)}</text>"
    )
    if caption:
        out.append(f'<text class="pct" x="60" y="77" text-anchor="middle">{escape(caption)}</text>')
    out.append("</svg>")
    return _svg("".join(out))


def percent_ring(pct: float, *, palette: str = "neon", label: str | None = None) -> Markup:
    """A thin circular progress ring with the percentage inside."""
    pct = min(100.0, max(0.0, pct))
    r = 28.0
    circ = 2 * math.pi * r
    gid = f"pr{abs(hash((palette, round(pct, 1)))) % 10_000_000}"
    return _svg(
        f'<svg viewBox="0 0 70 70" role="img" aria-label="{escape(label or f"{pct:.0f}%")}">'
        f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0" stop-color="{blend(palette, 0)}"/>'
        f'<stop offset="1" stop-color="{blend(palette, 1)}"/>'
        f"</linearGradient></defs>"
        f'<circle cx="35" cy="35" r="{r}" fill="#0f0b1e" stroke="{DIM}" stroke-width="4"/>'
        f'<circle cx="35" cy="35" r="{r}" fill="none" stroke="url(#{gid})" stroke-width="4" '
        f'stroke-linecap="round" '
        f'stroke-dasharray="{circ * pct / 100:.1f} {circ:.1f}" transform="rotate(-90 35 35)"/>'
        f'<text class="v" x="35" y="40" text-anchor="middle">{escape(label or f"{pct:.0f}%")}</text></svg>'
    )


def eq_bar(
    value: float, vmax: float, *, palette: str = "neon", segments: int = 28, log: bool = False
) -> Markup:
    """An equalizer row: lit segments in palette colours, the rest dim."""
    if log:
        frac = math.log10(1 + value) / math.log10(1 + vmax) if vmax > 0 else 0.0
    else:
        frac = value / vmax if vmax > 0 else 0.0
    lit = max(1 if value > 0 else 0, round(segments * frac))
    w = 100 / segments
    out = ['<svg viewBox="0 0 100 14" preserveAspectRatio="none" aria-hidden="true">']
    for i in range(segments):
        color = blend(palette, i / max(1, segments - 1)) if i < lit else "#241a40"
        out.append(
            f'<rect x="{i * w + 0.35:.2f}" y="0" width="{w - 0.7:.2f}" height="14" rx="0.6" fill="{color}"/>'
        )
    out.append("</svg>")
    return _svg("".join(out))


def grad_bar(pct: float, *, palette: str = "neon") -> Markup:
    """A 6 px gradient progress bar (width as an SVG attribute: no inline style)."""
    pct = min(100.0, max(0.0, pct))
    gid = f"gb{abs(hash((palette, round(pct, 2)))) % 10_000_000}"
    return _svg(
        f'<svg viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">'
        f'<defs><linearGradient id="{gid}"><stop offset="0" stop-color="{blend(palette, 0)}"/>'
        f'<stop offset="0.5" stop-color="{blend(palette, 0.5)}"/>'
        f'<stop offset="1" stop-color="{blend(palette, 1)}"/>'
        f"</linearGradient></defs>"
        f'<rect x="0" y="0" width="100" height="6" rx="3" fill="#241a40"/>'
        f'<rect x="0" y="0" width="{pct:.2f}" height="6" rx="3" fill="url(#{gid})"/></svg>'
    )


def timeline(rows: Sequence[tuple[str, datetime, datetime]], *, now: datetime, width: int = 720) -> Markup:
    """Sightings over time: one row per source, a bar from first to last report."""
    if not rows:
        return _svg('<p class="empty">No sightings.</p>')
    left, right, top, row_h = 120, 16, 10, 26
    start = min(r[1] for r in rows)
    span = max((now - start).total_seconds(), 3600.0)
    height = top + row_h * len(rows) + 26
    out = [
        f'<svg class="timeline" viewBox="0 0 {width} {height}" role="img" aria-label="Sightings timeline">'
    ]
    plot = width - left - right

    def x(t: datetime) -> float:
        return left + plot * max(0.0, (t - start).total_seconds()) / span

    for i, (label, first, last) in enumerate(rows):
        y = top + i * row_h + row_h / 2
        color = blend("neon", i / max(1, len(rows) - 1))
        x1, x2 = x(first), max(x(last), x(first) + 4)
        out.append(f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end">{escape(label)}</text>')
        out.append(
            f'<line class="axis" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" opacity="0.35"/>'
        )
        out.append(
            f'<line class="span" x1="{x1:.1f}" x2="{x2:.1f}" y1="{y:.1f}" y2="{y:.1f}" stroke="{color}">'
            f"<title>{escape(label)}: {first:%Y-%m-%d %H:%M} to {last:%Y-%m-%d %H:%M} UTC</title></line>"
        )
        out.append(f'<circle cx="{x2:.1f}" cy="{y:.1f}" r="4" fill="#fff"/>')
    yb = top + row_h * len(rows) + 16
    out.append(f'<text class="t" x="{left}" y="{yb}">{start:%Y-%m-%d}</text>')
    out.append(f'<text class="t" x="{width - right}" y="{yb}" text-anchor="end">now</text>')
    out.append("</svg>")
    return _svg("".join(out))


NODE_COLORS = {
    "malware": "#ff4fa3",
    "tool": "#ff9f45",
    "intrusion-set": "#ff4f7b",
    "campaign": "#ffd84d",
    "attack-pattern": "#8b5cf6",
    "vulnerability": "#ffc53d",
    "indicator": "#2ee6f0",
}


def radial_graph(center: str, nodes: Sequence[tuple[str, str, str, str]], *, width: int = 640) -> Markup:
    """The indicator in the middle and what it is linked to around it.
    ``nodes`` are (label, type, relationship, href); each node links to its page."""
    height = 330
    cx, cy, r = width / 2, height / 2, 125
    shown = list(nodes)[:14]
    out = [f'<svg class="graph" viewBox="0 0 {width} {height}" role="img" aria-label="Relationship graph">']
    pos = []
    for i in range(len(shown)):
        a = -math.pi / 2 + 2 * math.pi * i / max(1, len(shown))
        pos.append((cx + r * 1.35 * math.cos(a), cy + r * math.sin(a)))
    for (x, y), (_, _, rel, _) in zip(pos, shown, strict=True):
        out.append(f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{x:.1f}" y2="{y:.1f}"/>')
        out.append(
            f'<text class="rel" x="{(cx + x) / 2:.1f}" y="{(cy + y) / 2 - 3:.1f}" text-anchor="middle">'
            f"{escape(rel)}</text>"
        )
    for (x, y), (label, typ, _, href) in zip(pos, shown, strict=True):
        color = NODE_COLORS.get(typ, "#aaa0cc")
        anchor = "start" if x > cx + 8 else "end" if x < cx - 8 else "middle"
        dx = 13 if anchor == "start" else -13 if anchor == "end" else 0
        dy = 4 if anchor != "middle" else (-14 if y < cy else 22)
        short = label if len(label) <= 26 else label[:25] + "…"
        out.append(
            f'<a href="{escape(href)}"><title>{escape(typ)}: {escape(label)}</title>'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{color}"/>'
            f'<text x="{x + dx:.1f}" y="{y + dy:.1f}" text-anchor="{anchor}">{escape(short)}</text></a>'
        )
    out.append(f'<circle class="center" cx="{cx:.1f}" cy="{cy:.1f}" r="13"/>')
    out.append(
        f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="22" fill="none" stroke="#ff4fa3" stroke-opacity="0.35"/>'
    )
    c = center if len(center) <= 34 else center[:33] + "…"
    out.append(f'<text x="{cx:.1f}" y="{cy + 40:.1f}" text-anchor="middle">{escape(c)}</text>')
    if not shown:
        out.append(
            f'<text class="rel" x="{cx:.1f}" y="{cy - 30:.1f}" text-anchor="middle">no links yet</text>'
        )
    out.append("</svg>")
    return _svg("".join(out))
