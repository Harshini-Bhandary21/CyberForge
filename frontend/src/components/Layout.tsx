import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bot,
  Bug,
  CircleDollarSign,
  Database,
  ClipboardCheck,
  FileSearch,
  GraduationCap,
  LayoutDashboard,
  Moon,
  Play,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sun,
  Swords,
  UserCheck,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "@/api/client";
import type { Overview } from "@/api/types";
import { Badge, Button } from "@/components/ui";

const NAV: { group: string; items: { to: string; label: string; icon: LucideIcon; badge?: "approvals" | "incidents" }[] }[] = [
  {
    group: "1 · Monitor",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard },
      { to: "/guard", label: "Live Guard (try it)", icon: ShieldCheck },
      { to: "/approvals", label: "Approvals", icon: UserCheck, badge: "approvals" },
      { to: "/incidents", label: "Incidents", icon: Siren, badge: "incidents" },
    ],
  },
  {
    group: "2 · Check things",
    items: [
      { to: "/scanner", label: "Email Scam Check", icon: FileSearch },
      { to: "/behaviour", label: "Agent Behaviour", icon: Activity },
      { to: "/fraud", label: "Payment Fraud", icon: CircleDollarSign },
      { to: "/code", label: "Code Security", icon: Bug },
    ],
  },
  {
    group: "3 · Test & prove",
    items: [
      { to: "/compliance", label: "Compliance", icon: ClipboardCheck },
      { to: "/redteam", label: "Red Team", icon: Swords },
      { to: "/dojo", label: "Injection Dojo", icon: GraduationCap },
    ],
  },
];

function useTheme() {
  const [theme, setTheme] = useState<"light" | "dark" | null>(() => {
    try {
      return (localStorage.getItem("theme") as "light" | "dark" | null) ?? null;
    } catch {
      return null;
    }
  });
  useEffect(() => {
    const el = document.documentElement;
    if (theme) el.dataset.theme = theme;
    else delete el.dataset.theme;
    try {
      if (theme) localStorage.setItem("theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  const isDark = theme ? theme === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  return { isDark, toggle: () => setTheme(isDark ? "light" : "dark") };
}

export default function Layout() {
  const qc = useQueryClient();
  const { isDark, toggle } = useTheme();
  const overview = useQuery({ queryKey: ["overview"], queryFn: () => api.get<Overview>("/overview"), refetchInterval: 5_000 });
  const demo = useMutation({
    mutationFn: () => api.post("/demo/run"),
    onSuccess: () => qc.invalidateQueries(),
  });
  const counts = overview.data?.counts;
  const badge = { approvals: counts?.pending_approvals ?? 0, incidents: counts?.open_incidents ?? 0 };

  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-surface md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-[var(--accent)] to-[var(--grad-end)] text-white shadow-sm">
            <ShieldAlert size={18} aria-hidden />
          </span>
          <div>
            <div className="font-semibold leading-tight">AgentShield</div>
            <div className="text-[11px] text-ink-3">Keeps AI agents safe</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto px-3 pb-4" aria-label="Primary">
          {NAV.map((g) => (
            <div key={g.group} className="mt-4">
              <div className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wide text-ink-3">{g.group}</div>
              {g.items.map(({ to, label, icon: Icon, badge: b }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === "/"}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 rounded-lg border-l-2 px-2 py-1.5 text-sm transition ${isActive ? "border-accent bg-[var(--info-bg)] font-medium text-ink" : "border-transparent text-ink-2 hover:bg-surface-2"}`
                  }
                >
                  <Icon size={16} aria-hidden />
                  <span className="flex-1">{label}</span>
                  {b && badge[b] > 0 && (
                    <span className="rounded-full bg-critical px-1.5 text-[11px] font-medium text-white tabular-nums">{badge[b]}</span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="space-y-1.5 border-t border-line p-3 text-xs text-ink-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <Bot size={13} aria-hidden /> Judge:
            {overview.data?.engine.llm ? (
              overview.data.engine.providers.map((p) => (
                <Badge key={p} tone="good">
                  {p.split(":")[0]}
                </Badge>
              ))
            ) : (
              <Badge>heuristic (offline)</Badge>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <Database size={13} aria-hidden /> Store: <Badge>{overview.data?.engine.database ?? "…"}</Badge>
          </div>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-line bg-bg/90 px-5 py-2.5 backdrop-blur">
          <div className="flex items-center gap-2 text-ink-2 md:hidden">
            <ShieldAlert size={18} aria-hidden /> <span className="font-semibold text-ink">AgentShield</span>
          </div>
          <div className="hidden items-center gap-2 text-xs text-ink-3 md:flex">
            <Radar size={14} aria-hidden />
            {overview.isError ? "Backend unreachable. Start it with `make api`." : "Connected: all checks run live"}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="primary" title="Runs a scripted attack so you can see the shield respond" onClick={() => demo.mutate()} loading={demo.isPending}>
              <Play size={14} aria-hidden /> Watch a demo attack
            </Button>
            <Button variant="ghost" onClick={toggle} aria-label="Toggle theme">
              {isDark ? <Sun size={16} /> : <Moon size={16} />}
            </Button>
          </div>
        </header>
        <nav className="flex gap-1 overflow-x-auto border-b border-line bg-surface px-3 py-2 md:hidden" aria-label="Primary (mobile)">
          {NAV.flatMap((g) => g.items).map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs ${isActive ? "bg-surface-2 font-medium text-ink" : "text-ink-2"}`
              }
            >
              <Icon size={14} aria-hidden /> {label}
            </NavLink>
          ))}
        </nav>
        <main className="mx-auto max-w-6xl px-5 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
