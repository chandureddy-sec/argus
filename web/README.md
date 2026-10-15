# Argus web UI

The single front end of Argus: ReconX's attack-surface scans and ThreatLens's
threat intelligence behind one sign-in and one design. The platform API serves
the built files at `/app`.

```
npm install
npm run dev        # http://127.0.0.1:5173/app/ (needs the API on :8000)
npm run build      # dist/, built into the API image by threatlens/Dockerfile
```

* React 18 + TypeScript, Vite, Tailwind CSS 3, Recharts 3, lucide icons.
* **Theme ("Matte Rich", light and dark):** both palettes are CSS variables in
  `src/index.css` under `:root[data-theme]`; `tailwind.config.js` maps names onto
  them. Components never hard-code a colour; SVG charts read the same tokens with
  `useToken()` (`src/components/ui.tsx`) so they repaint on a theme switch. The
  switch is in the top bar; `src/lib/theme.tsx` remembers it per browser and
  `public/theme-init.js` applies it before the first paint.
* Indicator values are shown in their normal form (10.10.10.10, http://...): the
  API defangs what it sends and `live()` in `src/lib/ioc.ts` undoes it on arrival.
* Dialogs render through `Overlay` (a portal), never inside a card.
* Fonts are self-hosted (Inter, JetBrains Mono; SIL OFL, licences in
  `public/fonts`). No CDN: the API's CSP stays `script-src 'self'`.
* "Reduce motion" turns off entrance and chart animations.
