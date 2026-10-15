import { createContext, useContext, useEffect, type ReactNode } from "react";

/** Each page names itself; the top bar shows it as the breadcrumb and the tab title follows. */
type Crumbs = { set: (c: string[]) => void };
const Ctx = createContext<Crumbs>({ set: () => undefined });

export function CrumbsProvider({ set, children }: { set: (c: string[]) => void; children: ReactNode }) {
  return <Ctx.Provider value={{ set }}>{children}</Ctx.Provider>;
}

export function usePage(...crumbs: string[]) {
  const { set } = useContext(Ctx);
  const key = crumbs.join("›");
  useEffect(() => {
    set(crumbs);
    document.title = `${crumbs[crumbs.length - 1]} · Argus`;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
}
