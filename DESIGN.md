---
name: Argus
description: Matte Rich — a non-reflective precision instrument for recon and threat intel, in calm light and dark
colors:
  bg: "#1b1e26"
  card: "#252a34"
  card-2: "#2d333e"
  line: "#363c48"
  ctl-line: "#6f7686"
  ink: "#ece7dc"
  ink-muted: "#c2beb3"
  ink-faint: "#afaca2"
  accent: "#8f9a5b"
  accent-soft: "#c3c487"
  accent-hover: "#a3ad6c"
  on-accent: "#1b1e26"
  olive-gold: "#c2b464"
  teal: "#64b3ac"
  terracotta: "#e1936b"
  sage: "#9fb38f"
  plum: "#cd97b5"
  grey-teal: "#7a9ca1"
  up: "#7fbfa5"
  warn: "#e9a96b"
  down: "#eb9680"
  info: "#cfa2c1"
typography:
  display:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.01em"
  headline:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: "0em"
  body:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "0em"
  label:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0em"
  mono:
    fontFamily: "JetBrains Mono, ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "0em"
rounded:
  sm: "8px"
  ctl: "10px"
  card: "16px"
  full: "9999px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "20px"
  xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.ctl}"
    padding: "0 14px"
    height: "36px"
    typography: "{typography.label}"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
    textColor: "{colors.on-accent}"
  button-ghost:
    backgroundColor: "{colors.card-2}"
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.ctl}"
    padding: "0 14px"
    height: "36px"
  input:
    backgroundColor: "{colors.card-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.ctl}"
    padding: "0 12px"
    height: "36px"
  card:
    backgroundColor: "{colors.card}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card}"
    padding: "24px"
  chip:
    backgroundColor: "{colors.card-2}"
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.full}"
    padding: "2px 8px"
---

# Design System: Argus

## Overview

**Creative North Star: "The Matte Instrument"**

Argus is a precision instrument with a non-reflective finish. One operator stares
at it for hours, moving between attack-surface maps and threat-intel verdicts, so
every surface is calm and matte: deep navy-charcoal and olive in the dark theme,
warm beige and cream in the light one, with no glossy gradients, no colored glow,
and no decoration competing with the data. The identity is carried in the code's
own name for the theme — "Matte Rich" — and this document makes it normative.

Color is a scarce resource spent only on meaning. The interface is almost entirely
neutral; a single muted olive accent carries primary action and "you are here",
and a small set of earthen status hues (teal, terracotta, sage, plum) appear only
where they encode a finding, a metric, or a severity. The result reads as quiet
confidence: the screen is restful until something needs attention, and then the
one thing that matters is the only thing with color.

Components are refined and restrained. Borders are thin, radii are gentle, shadows
are a faint neutral lift rather than a drop, and interactive states shift tone by a
single step instead of announcing themselves. Density is comfortable but
information-first — this is an Operate surface, and scanability and consistency
outrank expression. The craft shows in the details: tabular-lining numerals,
monospace for every machine value, 4.5:1 text contrast enforced in both themes, and
motion that a reduced-motion preference fully disables.

**Key Characteristics:**
- Matte, non-reflective surfaces in two first-class themes (dark default, warm light).
- A single olive accent; color otherwise reserved for status and findings.
- Thin lines, gentle radii (10px controls, 16px cards), quiet neutral shadows.
- Inter for text, JetBrains Mono for every value; tabular numerals throughout.
- Calm at rest; state changes are one tonal step, never a glow.

## Colors

An earthen, desaturated palette: olive and warm neutrals as the ground, muted
jewel tones reserved for data and status. Values below are the dark (default)
theme; the light theme re-maps every token to warm beige/cream equivalents in
`src/index.css` and is equally canonical.

### Primary
- **Muted Olive** (`#8f9a5b` dark, `#5f6a34` light): the one accent and the
  **official Argus brand colour**. Primary buttons, active nav icon, the
  selected-tab fill, focus ring, selection highlight, and the logo "signal" dot.
  Used on a small fraction of any screen by design. (Pink `#ff4fa3` was explicitly
  rejected and retired on 2026-11-04; olive is the sole brand and interface accent.)
- **Olive Hover** (`#a3ad6c`): the single-step lift on primary-button hover.
- **Pale Olive** (`#c3c487`): olive used as *text* — links and accent labels where
  the solid fill would be too heavy.
- **On-Accent** (`#1b1e26`): the dark ink that sits on olive fills (reuses the
  background color for a cut-out look).

### Secondary — data-viz set
A six-hue categorical ramp for charts, KPI glyphs, and legends. Muted and equal in
weight so no series shouts over another.
- **Olive-Gold** (`#c2b464`): the primary line/series.
- **Teal** (`#64b3ac`), **Terracotta** (`#e1936b`), **Sage** (`#9fb38f`),
  **Plum** (`#cd97b5`), **Grey-Teal** (`#7a9ca1`): the remaining categorical hues
  and the secondary chart color.

### Tertiary — status
Semantic only; never decorative.
- **Up / Clean Teal-Green** (`#7fbfa5`): clean, active, positive change.
- **Warn / Soft Orange** (`#e9a96b`): suspicious, caution.
- **Down / Terracotta** (`#eb9680`): malicious, negative change.
- **Info / Plum** (`#cfa2c1`): monitor state, new, neutral-informational.

### Neutral
- **Deep Navy-Charcoal** (`#1b1e26`): app background.
- **Charcoal-Blue** (`#252a34`): cards and the sidebar.
- **Raised Charcoal** (`#2d333e`): inputs, table heads, popovers.
- **Divider** (`#363c48`): hairline borders and grid lines.
- **Control Line** (`#6f7686`): input and ghost-button borders.
- **Soft Grey-Beige** (`#ece7dc`): primary text.
- **Muted Beige** (`#c2beb3`): labels and secondary text.
- **Faint Beige** (`#afaca2`): hints and tertiary text.

### Named Rules
**The Signal Rule.** Color encodes meaning — status, a finding, a data series —
and nothing else. Chrome, containers, and layout stay neutral; a colored element
is always answerable to "what does this mean?"

**The One Accent Rule.** Olive is the only brand accent, and it carries primary
action and current-location. Never introduce a second competing accent; reach for
a neutral or a status hue instead.

## Typography

**Display / Body Font:** Inter (with ui-sans-serif, system-ui, Segoe UI, Roboto)
**Value / Mono Font:** JetBrains Mono (with ui-monospace, SFMono-Regular, Consolas)

**Character:** Inter set tight and quiet carries all human-readable text; JetBrains
Mono carries every machine value so an IP, hash, domain, or CVE is instantly
recognizable as data. Both are self-hosted (SIL OFL). The body enables Inter's
`cv11`, `ss01`, and `tnum` features, so numerals are tabular-lining everywhere.

### Hierarchy
- **Display** (Inter 700, 28px, line-height 1, -0.01em): the big KPI metric values;
  always tabular numerals.
- **Headline** (Inter 700, 17px, -0.01em): the product/page title (e.g. the sidebar
  wordmark).
- **Title** (Inter 600, 15px): card headers.
- **Body** (Inter 400–500, 14px, 1.5): default UI text, nav items, table cells.
- **Label** (Inter 500, 13px, color `ink-muted`): field labels, card subtitles;
  micro-labels drop to 11–12px in `ink-faint`.
- **Value / Mono** (JetBrains Mono, 13px): IPs, hashes, domains, CVE ids, tokens.

### Named Rules
**The Mono-for-Values Rule.** Any machine-generated value — IP, hash, domain, CVE,
API token — is set in JetBrains Mono with tabular numerals. Human prose is never
mono; values are never proportional.

## Layout

A fixed left sidebar (260px on mobile drawer, 240px on `lg`) holds the logo, a
global search, the grouped navigation, and the signed-in user; content fills the
rest. Cards are the primary container, arranged on a comfortable multi-column grid
that collapses to one column on small screens. Rhythm follows an 8px base: card
padding is 20px (`p-5`) rising to 24px (`p-6`) at `sm`; control height is a
consistent 36px (`h-9`); inline gaps are 8–12px. Density is information-first but
never cramped — generous vertical spacing between card header and body
(`mb-5`/20px). The single `lg` breakpoint (1024px) is the main responsive seam:
below it the sidebar becomes an overlay drawer with a blurred scrim.

## Elevation & Depth

Matte and nearly flat. Depth comes from tonal layering first — background →
card → raised control each step one tone lighter (dark) or one step toward white
(light) — and from hairline dividers, not from heavy shadows. Shadows exist but are
quiet and neutral: a soft card lift and a deeper popover shadow, never colored,
never a glow.

### Shadow Vocabulary
- **Card lift** (`--shadow-card`: `0 1px 0 rgb(255 255 255 / .025) inset, 0 10px 30px -18px rgb(0 0 0 / .6)` dark): the resting lift under every card; a faint inset top-highlight plus a diffuse drop.
- **Popover** (`--shadow-pop`: `0 16px 40px -12px rgb(0 0 0 / .55)` dark): dialogs, menus, popovers.
- **Selected** (`--shadow-sel`: `0 1px 2px rgb(0 0 0 / .35)` dark): the quiet lift on a selected tab or primary button — this is what `shadow-glow` maps to, deliberately not a glow.

### Named Rules
**The Matte Rule.** No colored glow, ever. A selected or hovered element lifts with
a neutral shadow and a one-step tonal change; it never emits light. `shadow-glow`
is a quiet neutral lift, not an accent halo.

## Shapes

A soft-rectangle language. Three radii do almost everything: 16px for cards
(`rounded-card`), 10px for controls — buttons, inputs, selects (`rounded-ctl`),
and 8px for the inner segments of a segmented control. Pills, avatars, status
chips, and the Change badge are fully round (`rounded-full`). Borders are a single
hairline in `line` (dividers) or `ctl-line` (interactive edges); there are no
double borders, no heavy frames, and no sharp 0-radius corners in the UI.

## Components

Refined and restrained: understated at rest, one-step tonal shifts on interaction,
color spent only where it carries meaning.

### Buttons
- **Shape:** 10px radius (`rounded-ctl`), 36px tall (`h-9`), 14px horizontal padding, medium weight, icon+label with an 8px gap.
- **Primary:** olive fill (`accent`) with dark `on-accent` text and the quiet `shadow-sel` lift; hover shifts to `accent-hover`. Used for the single most important action in a view (e.g. the sidebar's "Verify an indicator").
- **Ghost:** transparent-ish `card-2` at 60% with a `ctl-line` border and `ink-muted` text; hover brings text to `ink` and the border to `accent/40`. The default for secondary actions.
- **Focus:** a 2px `accent` outline offset 2px (global `:focus-visible`), plus a soft `accent/20` ring on fields.

### Chips / Pills
- **Chip:** fully round, `chip` fill (a ~12–14% neutral wash) with `chip-ink` text; for tags and metadata.
- **Change badge:** round, `up`/`down` at 10% fill with a matching 20% ring and bold tabular `tnum` text; encodes positive/negative change, invertible for metrics where down is good.
- **KPI glyph:** a 28px rounded-lg tile, one data-viz hue per metric at ~12–15% fill with a 1px ring (teal/terracotta/sage/plum).

### Cards / Containers
- **Corner Style:** 16px radius (`rounded-card`).
- **Background:** `card`, on the `bg` canvas.
- **Shadow Strategy:** the resting `--shadow-card` lift (see Elevation).
- **Border:** a single `line` hairline.
- **Internal Padding:** 20px (`p-5`), 24px (`p-6`) at `sm`; header separated from body by 20px.
- **Entrance:** a 0.45s `rise` (6px up + fade), staggerable via `delay`, fully disabled under reduced-motion.

### Inputs / Fields
- **Style:** 36px tall, 10px radius, `ctl-line` border, `card-2` at ~70% fill, `ink` text, `ink-faint` placeholder.
- **Focus:** border shifts to `accent/60` and a 2px `accent/20` ring appears — a tonal shift, not a glow.
- **Select:** same `ctl` base with a trailing chevron in `ink-muted`; options render on a `card` background.

### Navigation
- **Style:** a grouped sidebar. Top-level groups (Home, Attack surface, Threat intel, Response, Platform) are 40px rows with a Lucide icon; the active group's icon turns olive (`accent`) and its label goes to full `ink`.
- **Children:** indented under a 2px `line` rail; the active child gets a `tint` (olive wash) background, full-`ink` medium text, and a 2px olive marker bar on the rail. Inactive children are `ink-muted`, hovering to a `card-2` fill.
- **Mobile:** below `lg`, the sidebar slides in as a 260px drawer over a blurred `bg/70` scrim.

### Dialogs / Overlays
- Rendered in a body-level portal over a `scrim` backdrop with a light `backdrop-blur-sm`; content is centered and scrolls when tall. Kept out of animated/transformed ancestors so `position: fixed` is never clipped.

## Do's and Don'ts

### Do:
- **Do** route every color through `src/index.css` tokens (Tailwind names like `bg-card`, `text-ink-muted`, `bg-accent`); components never hard-code a hex.
- **Do** read colors for SVG/chart fills through `useToken()` so they re-resolve on theme change.
- **Do** set every machine value (IP, hash, domain, CVE, token) in `font-mono` with tabular numerals.
- **Do** keep both themes correct and ≥4.5:1 for text / ≥3:1 for controls and chart marks when adding or changing a color.
- **Do** convey depth with tonal layering and a hairline first; reach for a shadow only for cards, popovers, and the quiet selected lift.
- **Do** honor `prefers-reduced-motion`: the `rise` entrance and chart animations must fully stop.

### Don't:
- **Don't** add a colored glow, neon, or accent halo — `shadow-glow` is a quiet neutral lift by definition (The Matte Rule).
- **Don't** introduce a second brand accent; olive alone carries primary action and current-location (The One Accent Rule).
- **Don't** spend a status or data-viz hue on decoration; color must encode meaning (The Signal Rule).
- **Don't** hard-code light- or dark-specific colors in a component; theme them through tokens so both modes stay correct.
- **Don't** use sharp 0-radius corners or double borders; the form language is soft rectangles with single hairlines.
