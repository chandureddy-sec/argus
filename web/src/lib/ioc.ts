/* Indicators on screen are defanged (inert when copied); refanging happens only
 * on an explicit "Copy" click. The server already defangs what it sends; this
 * covers free text such as feed context. */

const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const DOMAIN = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+)([a-z]{2,24})\b/gi;

export function defang(text: string): string {
  if (text.includes("[.]")) return text; // already defanged
  return text
    .replace(/\bhttp(s?):\/\//gi, "hxxp$1[://]")
    .replace(IPV4, "$1[.]$2[.]$3[.]$4")
    .replace(DOMAIN, (_m, labels: string, tld: string) => `${labels.slice(0, -1).replace(/\./g, "[.]")}[.]${tld}`);
}

export function refang(text: string): string {
  return text
    .replace(/\[:\/\/\]/g, "://")
    .replace(/\[\.\]/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]/g, "@")
    .replace(/^hxxp/i, "http")
    .replace(/^fxp/i, "ftp");
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
