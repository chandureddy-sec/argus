const DT = new Intl.DateTimeFormat("en", { month: "short", day: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
const D = new Intl.DateTimeFormat("en", { month: "short", day: "2-digit", year: "numeric" });

/** Go's zero time ("0001-01-01T00:00:00Z") means "never". */
function valid(iso?: string | null): Date | null {
  if (!iso || iso.startsWith("0001-")) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

export const dateTime = (iso?: string | null) => (valid(iso) ? DT.format(valid(iso)!) : "–");
export const date = (iso?: string | null) => (valid(iso) ? D.format(valid(iso)!) : "–");

export function ago(iso?: string | null): string {
  const d = valid(iso);
  if (!d) return "never";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  const future = s < 0;
  const a = Math.abs(s);
  const [n, unit] = a < 60 ? [a, "s"] : a < 3600 ? [Math.round(a / 60), "min"] : a < 86400 ? [Math.round(a / 3600), "h"] : [Math.round(a / 86400), "d"];
  return future ? `in ${n} ${unit}` : `${n} ${unit} ago`;
}

/** A scan's reference in URLs: saved file name, or job:<id> for an unsaved scan. */
export const scanRef = (row: { file?: string; job_id?: string }) => row.file ?? `job:${row.job_id}`;
