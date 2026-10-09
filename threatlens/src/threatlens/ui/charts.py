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
from functools import lru_cache
from pathlib import Path
from typing import Any

from markupsafe import Markup, escape

Point = tuple[float, float]


def _svg(markup: str) -> Markup:
    """Mark built SVG/HTML as safe. Every value interpolated into it is a
    number formatted here or text passed through ``escape()``."""
    return Markup(markup)  # noqa: S704 - see docstring


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
) -> Markup:
    """A smooth line with a soft fill. ``series`` is [(label, value)]."""
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
        f'<stop offset="0" stop-color="{color}" stop-opacity="0.35"/>'
        f'<stop offset="1" stop-color="{color}" stop-opacity="0"/></linearGradient></defs>',
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
