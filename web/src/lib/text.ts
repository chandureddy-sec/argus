/** ATT&CK and NVD descriptions as plain text: markdown links keep their words,
 * "(Citation: …)" markers go. Rendered as text, never as HTML. */
export function plain(md: string | null | undefined): string {
  return (md ?? "")
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, "$1")
    .replace(/<\/?code>/g, "")
    .replace(/\s+\./g, ".")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

/** Only Argus paths are valid post-login targets (no open redirect). */
export function safeNext(next: string | null): string {
  if (!next || !next.startsWith("/app/") || next.includes("//") || next.includes("\\")) return "/app/";
  return next;
}
