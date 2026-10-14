# Unified web UI (working name: Argus)

The single front end for the merged platform: ReconX's recon engine and
ThreatLens's threat intelligence behind one login and one design.

```
npm install
npm run dev        # http://127.0.0.1:5173/app/
npm run build      # dist/, served by the platform API under /app
```

* React 18 + TypeScript, Vite, Tailwind CSS 3, Recharts 3, lucide icons.
* Design tokens: CSS variables in `src/index.css` (RGB triplets), mapped in
  `tailwind.config.js`. Components never hard-code a colour; charts read the
  same tokens through `token()` in `src/components/ui.tsx`.
* Fonts are self-hosted (Inter, JetBrains Mono; SIL OFL, licences in
  `public/fonts`). No CDN: the API's CSP stays `script-src 'self'`.
* "Reduce motion" turns off entrance and chart animations.
* `src/data/sample.ts` is design-pass sample data in the shapes the API will serve.
