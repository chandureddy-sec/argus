# Product marks

One family for every tool built in this repository: ReconX, ThreatLens and whatever comes next.
A new product looks related at a glance but stays distinguishable in a browser tab.

| Product | Mark | Gradient (bottom-left → top-right) | Glyph |
|---|---|---|---|
| ThreatLens | `threatlens.svg` | `#ff4fa3` → `#8b5cf6` → `#2ee6f0` | a lens closing in on a threat |
| ReconX | `reconx.svg` | `#a7e9c6` → `#34d3b4` → `#22d3ee` | a radar sweep whose beam points at the signal |
| next product | start from `template.svg` | pick three stops not used above | one idea, drawn in 2–4 strokes |

## What every mark shares (don't change these)
* **Frame**: 64 × 64 view box, rounded square `x=3 y=3 w=58 h=58 rx=17`, fill `#0e0b1d`, 2.5 stroke in
  the product gradient.
* **Signal**: a filled circle at `(48, 16)`, radius 4, family pink `#ff4fa3`. It is the "finding"
  every product exists to surface. Same place, size and colour everywhere.
* **Glyph strokes**: 4.5 wide (5.5 for at most one emphasis stroke), round caps, product gradient,
  inside 13–51 on both axes, clear of the signal corner.

## What each product chooses
* The gradient (three stops, dark to light, at 0, ~.5 and 1).
* The glyph: one idea a person could describe in four words.
* Gradient ids must be unique per mark (`tl-g`, `rx-g`, …) so two marks can share a page.

## Wordmark
The product name set in **Inter** 700 (`letter-spacing: -0.01em`), next to the mark at the mark's
height. Products with a two-part name may colour the second part in the gradient's last stop
(Threat**Lens**, Recon**X**). Interfaces use Inter for text and JetBrains Mono for values (IPs,
hashes, domains); both are SIL OFL and self-hosted.

## Using a mark
* Favicon and header: link the SVG directly (`<link rel="icon" type="image/svg+xml" href=…>`).
* Smallest size: 16 px. Below 24 px the signal still reads; nothing else may be added.
* On light backgrounds use the mark as is: the frame carries its own dark fill.
* Copies live in each app (`threatlens/src/threatlens/ui/static/logo.svg`,
  `internal/cli/webui/logo.svg`); this folder is the source. Change it here, then copy.

`preview.html` shows every mark at 16, 24, 32, 64 and 128 px on dark and light backgrounds.
