"""Build the dotted world map used by the dashboard.

Input: Natural Earth 1:110m admin-0 countries GeoJSON (public domain), e.g.
https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson

Output: src/threatlens/ui/worldmap.json with
* ``dots``: [lon, lat] grid points (every ``step`` degrees) that fall on land;
* ``countries``: ISO 3166-1 alpha-2 → [lon, lat, name] label point.

Usage:  python scripts/build_worldmap.py path/to/countries.geojson
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

STEP = 2.0
LAT_MIN, LAT_MAX = -56.0, 82.0  # Antarctica and the high Arctic add nothing here

Ring = list[tuple[float, float]]


def _rings(geom: dict[str, Any]) -> list[list[Ring]]:
    polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
    return [[[(float(x), float(y)) for x, y in ring] for ring in poly] for poly in polys]


def _inside(x: float, y: float, ring: Ring) -> bool:
    hit = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i]
        xj, yj = ring[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            hit = not hit
        j = i
    return hit


def on_land(x: float, y: float, polys: list[list[Ring]]) -> bool:
    for outer, *holes in polys:
        if _inside(x, y, outer) and not any(_inside(x, y, h) for h in holes):
            return True
    return False


def main(src: Path) -> None:
    features = json.loads(src.read_text(encoding="utf-8"))["features"]
    shapes = []
    countries: dict[str, list[Any]] = {}
    for f in features:
        p = f["properties"]
        iso = p.get("ISO_A2_EH") if p.get("ISO_A2") in (None, "-99") else p.get("ISO_A2")
        polys = _rings(f["geometry"])
        xs = [x for poly in polys for x, _ in poly[0]]
        ys = [y for poly in polys for _, y in poly[0]]
        shapes.append((min(xs), max(xs), min(ys), max(ys), polys))
        if iso and iso != "-99":
            countries[iso] = [round(p["LABEL_X"], 2), round(p["LABEL_Y"], 2), p["NAME"]]
    dots = []
    lat = LAT_MAX
    while lat >= LAT_MIN:
        lon = -180.0 + STEP / 2
        while lon < 180:
            for x0, x1, y0, y1, polys in shapes:
                if x0 <= lon <= x1 and y0 <= lat <= y1 and on_land(lon, lat, polys):
                    dots.append([lon, lat])
                    break
            lon += STEP
        lat -= STEP
    out = Path(__file__).resolve().parents[1] / "src" / "threatlens" / "ui" / "worldmap.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "source": "Natural Earth 1:110m admin-0 countries (public domain)",
                "step": STEP,
                "lat_min": LAT_MIN,
                "lat_max": LAT_MAX,
                "dots": dots,
                "countries": dict(sorted(countries.items())),
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    print(f"{len(dots)} land dots, {len(countries)} countries -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
