import { createContext, useContext, useEffect, type ReactNode } from "react";

/** Each page names itself; the top bar shows it as the breadcrumb and the tab title follows. */
type Crumbs = { set: (c: string[]) => void };
const Ctx = createContext<Crumbs>({ set: () => undefined });

export function CrumbsProvider({ set, children }: { set: (c: string[]) => void; children: ReactNode }) {
  return <Ctx.Provider value={{ set }}>{children}</Ctx.Provider>;
}

/** Threat-intel pages wear their own palette (ti-palette.css, class "ti"). */
const TI_PAGES = ["/landscape", "/verify", "/bulk", "/indicators", "/vulnerabilities", "/attack", "/entities", "/search", "/cases", "/blocklist", "/feeds"];

export function scopeFor(path: string): string {
  return TI_PAGES.some((p) => path === p || path.startsWith(`${p}/`)) ? "ti" : "";
}

/** The colour scope of the current page ("" = the :root theme), for code that needs concrete colours. */
const Scope = createContext("");
export const ScopeProvider = Scope.Provider;
export const useScope = () => useContext(Scope);

export function usePage(...crumbs: string[]) {
  const { set } = useContext(Ctx);
  const key = crumbs.join("›");
  useEffect(() => {
    set(crumbs);
    document.title = `${crumbs[crumbs.length - 1]} · Argus`;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
}
