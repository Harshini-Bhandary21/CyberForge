export const pct = (x: number, digits = 0) => `${(x * 100).toFixed(digits)}%`;

export function timeAgo(ts: number): string {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const clock = (ts: number) =>
  new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const titleCase = (s: string) =>
  s
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

/** Turn a backend identifier (send_email, R-TAINT-001, guard.decision, uuid) into plain words. */
export function humanize(id: string): string {
  const rule = /^R-([A-Z]+)-\d+$/.exec(id);
  if (rule) return `${titleCase(rule[1].toLowerCase())} check`;
  if (/^[0-9a-f-]{12,}$/i.test(id)) return `#${id.replace(/-/g, "").slice(0, 6)}`;
  const t = id.replace(/[._:/\-]+/g, " ").replace(/\s+/g, " ").trim().toLowerCase();
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export const short = (s: string, n = 60) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function download(filename: string, text: string, mime = "text/markdown") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
