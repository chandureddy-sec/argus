/** Design tokens live in src/index.css as CSS variables (RGB triplets), one set
 * per theme (light/dark); Tailwind only maps names onto them. */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        card: v("card"),
        "card-2": v("card-2"),
        line: v("line"),
        accent: { DEFAULT: v("accent"), soft: v("accent-soft"), muted: v("accent-muted"), hover: v("accent-hover") },
        ink: { DEFAULT: v("ink"), muted: v("ink-muted"), faint: v("ink-faint") },
        up: v("up"),
        down: v("down"),
        warn: v("warn"),
        // Role tokens (see index.css). The last four are full colours with their
        // alpha built in, so they take no /opacity modifier.
        "on-accent": v("on-accent"),
        "ctl-line": v("ctl-line"),
        info: { DEFAULT: v("info"), soft: v("info-soft") },
        "chip-ink": v("chip-ink"),
        chip: "var(--chip)",
        tint: "var(--tint)",
        "row-hover": "var(--row-hover)",
        zebra: "var(--zebra)",
        scrim: "var(--scrim)",
        knob: v("knob"),
        // data viz (Matte Rich): primary line, bar pair, pie set
        "olive-gold": v("olive-gold"),
        teal: v("teal"),
        terracotta: v("terracotta"),
        sage: v("sage"),
        plum: v("plum"),
        "grey-teal": v("grey-teal"),
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
      // 12% is used for tinted chips and pills (bg-down/12); not in the default scale
      opacity: { 12: "0.12" },
      borderRadius: { card: "16px", ctl: "10px" },
      boxShadow: {
        // matte: a quiet lift for selected tabs, no coloured glow
        glow: "var(--shadow-sel)",
        pop: "var(--shadow-pop)",
      },
      keyframes: {
        rise: { from: { opacity: "0", transform: "translateY(6px)" }, to: { opacity: "1", transform: "none" } },
      },
      // "backwards", not "both": a finished animation must not keep its transform,
      // or the card would trap position:fixed children (dialogs) inside it.
      animation: { rise: "rise .45s cubic-bezier(.2,.7,.2,1) backwards" },
    },
  },
  plugins: [],
};
