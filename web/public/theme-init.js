// Runs before the page paints: apply the saved (or system) theme so the page
// never flashes the other one. Same logic as applyTheme() in src/lib/theme.tsx.
// A separate file because the CSP allows only same-origin scripts, no inline.
(function () {
  var t = null;
  try {
    t = localStorage.getItem("argus-theme");
  } catch (e) {
    /* storage blocked: fall back to the system setting */
  }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", t);
})();
