/* Values are shown in their normal form (10.10.10.10, http://...). The API
 * still defangs what it sends (exports and the REST API keep that), so the app
 * turns its defang markers back into the real characters as data arrives
 * (live() in lib/api.ts). Only the exact markers the server writes are undone:
 * [.] [:] [@] [://] and the hxxp / fxp schemes in front of "://". */

export function refang(text: string): string {
  return text
    .replace(/\[:\/\/\]/g, "://")
    .replace(/\[\.\]/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]/g, "@")
    .replace(/\bhxxp(s?)(?=:\/\/)/gi, "http$1")
    .replace(/\bfxp(?=:\/\/)/gi, "ftp");
}

/** refang() on every string in a JSON value (object keys are left alone). */
export function live<T>(v: T): T {
  if (typeof v === "string") return refang(v) as T;
  if (Array.isArray(v)) return v.map(live) as T;
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, live(x)])) as T;
  return v;
}

export async function copyRefanged(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(refang(text));
    return true;
  } catch {
    return false;
  }
}

export const TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] as const;
export type Tlp = (typeof TLPS)[number];

export const TYPE_LABEL: Record<string, string> = {
  "ipv4-addr": "IPv4 address",
  "ipv6-addr": "IPv6 address",
  "ipv4-net": "IP range",
  "ipv6-net": "IPv6 range",
  "domain-name": "Domain",
  url: "URL",
  "email-addr": "Email address",
  "file-md5": "MD5 hash",
  "file-sha1": "SHA-1 hash",
  "file-sha256": "SHA-256 hash",
  vulnerability: "CVE",
  "file-name": "File name",
  "windows-registry-key": "Registry key",
};

export const BLOCKABLE = new Set(["ipv4-addr", "ipv6-addr", "ipv4-net", "ipv6-net", "domain-name", "url"]);

export function verdictOf(score: number | null | undefined): "malicious" | "suspicious" | "unknown" {
  if (score == null) return "unknown";
  return score >= 60 ? "malicious" : score >= 30 ? "suspicious" : "unknown";
}
