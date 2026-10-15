import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

/** Light / dark. The choice is kept in this browser (localStorage); without one
 * the system setting decides and is followed live. index.css holds both palettes
 * under :root[data-theme]. */
export type Theme = "light" | "dark";

const KEY = "argus-theme";
const SYSTEM = "(prefers-color-scheme: light)";

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null; // private mode or blocked storage: fall back to the system
  }
}

function system(): Theme {
  return window.matchMedia?.(SYSTEM).matches ? "light" : "dark";
}

/** Set before the first render so the page never flashes the other theme. */
export function applyTheme(t: Theme = stored() ?? system()): Theme {
  document.documentElement.dataset.theme = t;
  // the browser's own bars (mobile address bar, PWA title) follow the page
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", t === "light" ? "#ebe6dc" : "#1b1e26");
  return t;
}

const Ctx = createContext<{ theme: Theme; setTheme: (t: Theme) => void }>({ theme: "dark", setTheme: () => undefined });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, set] = useState<Theme>(() => (document.documentElement.dataset.theme as Theme | undefined) ?? applyTheme());
  const setTheme = useCallback((t: Theme) => {
    applyTheme(t); // before the re-render, so colours read during render are the new ones
    try {
      localStorage.setItem(KEY, t);
    } catch {
      /* the switch still works for this visit */
    }
    set(t);
  }, []);
  useEffect(() => {
    const mq = window.matchMedia?.(SYSTEM);
    if (!mq) return;
    const follow = () => {
      if (stored()) return; // an explicit choice wins over the system
      set(applyTheme(system()));
    };
    mq.addEventListener("change", follow);
    return () => mq.removeEventListener("change", follow);
  }, []);
  return <Ctx.Provider value={{ theme, setTheme }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
