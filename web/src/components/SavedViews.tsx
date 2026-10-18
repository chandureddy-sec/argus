import { Bookmark, Loader2, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { send, useApi, type SavedSearch } from "../lib/api";

const BASE = "/app/api/searches";

/** Saved searches and filtered views for this account: a row of links, and
 * "Save this view" for the page as it is now (path + query string). */
export function SavedViews({ canSave = true }: { canSave?: boolean }) {
  const loc = useLocation();
  const { data, reload } = useApi<SavedSearch[]>("searches");
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const here = `${loc.pathname}${loc.search}`;
  const saved = data?.find((s) => s.query === here);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await send("POST", BASE, { name: name.trim(), query: here });
      setNaming(false);
      setName("");
      reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (id: number) => {
    try {
      await send("DELETE", `${BASE}/${id}`);
    } finally {
      reload();
    }
  };

  if (!data?.length && !canSave) return null;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[12.5px]">
      {data?.map((s) => (
        <span key={s.id} className={`inline-flex items-center rounded ring-1 ${s.query === here ? "bg-accent/15 ring-accent/40" : "bg-chip ring-line"}`}>
          <Link to={s.query} className="py-1 pl-2 pr-1 text-chip-ink hover:text-accent-soft" title={s.query}>
            {s.name}
          </Link>
          <button type="button" className="px-1.5 py-1 text-ink-faint hover:text-down" aria-label={`Delete saved view ${s.name}`} onClick={() => remove(s.id)}>
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      {canSave && !saved && loc.search && (naming ? (
        <form onSubmit={save} className="inline-flex items-center gap-1.5">
          <input value={name} onChange={(e) => setName(e.target.value)} className="ctl h-7 w-44 text-[12.5px]" placeholder="Name this view" maxLength={100} autoFocus />
          <button className="btn-primary h-7 px-2.5 text-[12.5px]" disabled={!name.trim() || busy}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Save"}
          </button>
          <button type="button" className="btn-ghost h-7 px-2 text-[12.5px]" onClick={() => setNaming(false)}>
            Cancel
          </button>
        </form>
      ) : (
        <button type="button" className="btn-ghost h-7 px-2.5 text-[12.5px]" onClick={() => setNaming(true)}>
          <Bookmark className="h-3.5 w-3.5" /> Save this view
        </button>
      ))}
      {error && <span className="text-down">{error}</span>}
    </div>
  );
}
