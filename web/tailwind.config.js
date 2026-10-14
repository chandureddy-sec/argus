/** Design tokens live in src/index.css as CSS variables (RGB triplets), so a
 * theme change is one edit there; Tailwind only maps names onto them. */
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
        accent: { DEFAULT: v("accent"), soft: v("accent-soft"), muted: v("accent-muted") },
        ink: { DEFAULT: v("ink"), muted: v("ink-muted"), faint: v("ink-faint") },
        up: v("up"),
        down: v("down"),
        warn: v("warn"),
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
      borderRadius: { card: "16px", ctl: "10px" },
      boxShadow: {
        glow: "0 0 0 1px rgb(var(--accent) / 0.35), 0 8px 24px -8px rgb(var(--accent) / 0.55)",
      },
      keyframes: {
        rise: { from: { opacity: "0", transform: "translateY(6px)" }, to: { opacity: "1", transform: "none" } },
      },
      animation: { rise: "rise .45s cubic-bezier(.2,.7,.2,1) both" },
    },
  },
  plugins: [],
};
