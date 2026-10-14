/* Realistic sample data for the design pass. Every shape here matches what the
 * platform API will serve, so wiring the real endpoints replaces this file. */

export type Range = "Year" | "Month" | "Week" | "Day";

export interface Kpi {
  label: string;
  value: string;
  change: number; // percent vs the previous period
  icon: "radar" | "server" | "alert" | "timer";
  hint: string;
}

export const kpis: Kpi[] = [
  { label: "Indicators ingested", value: "60.8K", change: 12.4, icon: "radar", hint: "from 14 feeds" },
  { label: "Assets monitored", value: "20.6K", change: 4.2, icon: "server", hint: "hosts, IPs, domains" },
  { label: "New exposures", value: "756", change: -3.1, icon: "alert", hint: "open ports, weak TLS, leaks" },
  { label: "Mean time to verify", value: "10min", change: -18.6, icon: "timer", hint: "alert to verdict" },
];

export interface Point {
  label: string; // axis label
  date: string; // tooltip date
  malicious: number;
  suspicious: number;
}

// Deterministic pseudo-random so the charts don't jump between renders.
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

function series(labels: string[], dates: string[], base: number, swing: number, seed: number): Point[] {
  const r = rng(seed);
  return labels.map((label, i) => {
    const wave = Math.sin((i / Math.max(1, labels.length - 1)) * Math.PI * 1.6 + seed) * swing;
    const m = Math.round(base + wave + r() * swing * 0.6);
    return { label, date: dates[i], malicious: m, suspicious: Math.round(m * (0.42 + r() * 0.18)) };
  });
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export const activity: Record<Range, Point[]> = {
  Year: series(MONTHS, MONTHS.map((m, i) => `${m} ${String(4 + ((i * 7) % 24)).padStart(2, "0")}, 2026`), 34000, 12000, 3),
  Month: series(
    Array.from({ length: 30 }, (_, i) => String(i + 1)),
    Array.from({ length: 30 }, (_, i) => `Sep ${String(i + 1).padStart(2, "0")}, 2026`),
    1200, 420, 7,
  ),
  Week: series(DAYS, DAYS.map((_, i) => `Oct ${String(5 + i).padStart(2, "0")}, 2026`), 1300, 380, 11),
  Day: series(
    Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, "0")}:00`),
    Array.from({ length: 24 }, (_, i) => `Oct 14, 2026 · ${String(i).padStart(2, "0")}:00`),
    54, 22, 5,
  ),
};

export const activityTotal: Record<Range, { value: string; change: number }> = {
  Year: { value: "240.8K", change: 8.6 },
  Month: { value: "36.4K", change: 5.1 },
  Week: { value: "9.1K", change: -2.4 },
  Day: { value: "1.3K", change: 11.9 },
};

export interface Ring {
  name: string;
  value: number;
  color: string; // a token name: accent | accent-soft | accent-muted
}

export const platforms: Record<string, Ring[]> = {
  "All environments": [
    { name: "Linux servers", value: 11204, color: "accent" },
    { name: "Windows hosts", value: 8836, color: "accent-soft" },
    { name: "Network devices", value: 4608, color: "accent-muted" },
  ],
  Production: [
    { name: "Linux servers", value: 7310, color: "accent" },
    { name: "Windows hosts", value: 3920, color: "accent-soft" },
    { name: "Network devices", value: 2210, color: "accent-muted" },
  ],
  "Cloud only": [
    { name: "Linux servers", value: 5402, color: "accent" },
    { name: "Windows hosts", value: 1290, color: "accent-soft" },
    { name: "Network devices", value: 640, color: "accent-muted" },
  ],
};

export interface ScanDay {
  day: string;
  passive: number;
  active: number;
}

export const scans: Record<string, ScanDay[]> = {
  "This week": [
    { day: "Mon", passive: 42, active: 18 }, { day: "Tue", passive: 55, active: 24 },
    { day: "Wed", passive: 48, active: 31 }, { day: "Thu", passive: 63, active: 27 },
    { day: "Fri", passive: 58, active: 35 }, { day: "Sat", passive: 21, active: 9 },
    { day: "Sun", passive: 17, active: 6 },
  ],
  "Last week": [
    { day: "Mon", passive: 38, active: 15 }, { day: "Tue", passive: 47, active: 20 },
    { day: "Wed", passive: 52, active: 22 }, { day: "Thu", passive: 49, active: 29 },
    { day: "Fri", passive: 61, active: 26 }, { day: "Sat", passive: 18, active: 11 },
    { day: "Sun", passive: 14, active: 4 },
  ],
};

export type IocType = "ip" | "domain" | "url" | "hash";
export type Status = "Active" | "Expired";

export interface Row {
  id: number;
  value: string; // defanged for display
  type: IocType;
  source: string;
  date: string;
  location: string;
  status: Status;
  score: number;
}

export const indicators: Row[] = [
  { id: 1, value: "185.220.101[.]34", type: "ip", source: "Feodo Tracker", date: "Oct 14, 2026", location: "Germany", status: "Active", score: 92 },
  { id: 2, value: "login-microsoftonline-verify[.]top", type: "domain", source: "OpenPhish", date: "Oct 14, 2026", location: "Netherlands", status: "Active", score: 88 },
  { id: 3, value: "45.155.205[.]233", type: "ip", source: "AbuseIPDB", date: "Oct 13, 2026", location: "Russia", status: "Active", score: 81 },
  { id: 4, value: "hxxp://cdn-update-check[.]xyz/payload.bin", type: "url", source: "URLhaus", date: "Oct 13, 2026", location: "United States", status: "Active", score: 77 },
  { id: 5, value: "e3b0c442…b855", type: "hash", source: "MalwareBazaar", date: "Oct 12, 2026", location: "—", status: "Active", score: 74 },
  { id: 6, value: "162.243.103[.]246", type: "ip", source: "Feodo Tracker", date: "Oct 10, 2026", location: "United States", status: "Expired", score: 21 },
  { id: 7, value: "invoice-portal-secure[.]online", type: "domain", source: "ThreatFox", date: "Oct 09, 2026", location: "Singapore", status: "Active", score: 69 },
  { id: 8, value: "91.92.248[.]117", type: "ip", source: "Spamhaus DROP", date: "Oct 08, 2026", location: "Bulgaria", status: "Expired", score: 34 },
  { id: 9, value: "hxxps://drive-share-docs[.]click/view", type: "url", source: "OpenPhish", date: "Oct 07, 2026", location: "France", status: "Expired", score: 28 },
  { id: 10, value: "103.145.13[.]88", type: "ip", source: "Your feed · Partner SOC", date: "Oct 07, 2026", location: "India", status: "Active", score: 63 },
  { id: 11, value: "9f86d081…0f00a08", type: "hash", source: "MalwareBazaar", date: "Oct 06, 2026", location: "—", status: "Active", score: 85 },
  { id: 12, value: "tor-exit-relay[.]net", type: "domain", source: "Tor exit list", date: "Oct 05, 2026", location: "Romania", status: "Expired", score: 18 },
];
