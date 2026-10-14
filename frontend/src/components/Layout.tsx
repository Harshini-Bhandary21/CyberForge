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
  ShieldCheck,
  Siren,
  Sun,
  Swords,
  UserCheck,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { api } from "@/api/client";
import type { Overview } from "@/api/types";
import { Badge, Button } from "@/components/ui";

const NAV: { group: string; items: { to: string; label: string; icon: LucideIcon; badge?: "approvals" | "incidents" }[] }[] = [
  {
    group: "1 · Monitor",
    items: [
      { to: "/overview", label: "Overview", icon: LayoutDashboard },
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
    <div className="flex min-h-full bg-bg text-ink">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-line bg-surface md:flex">
        <div className="flex items-center justify-between px-4 py-4 border-b border-line">
          <div className="flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-xl bg-neutral-900 text-[#a3e635] dark:bg-white/10 dark:text-[#a3e635] border border-line shadow-sm">
              <ShieldCheck size={18} aria-hidden />
            </span>
            <div>
              <div className="font-bold text-sm tracking-tight leading-tight">AgentShield</div>
              <div className="text-[10px] font-mono text-ink-3">Team Eklavya</div>
            </div>
          </div>
          <Link
            to="/"
            title="Return to Landing Page"
            className="text-[10px] font-mono font-medium px-2.5 py-1 rounded-full bg-surface-2 hover:bg-[#a3e635] hover:text-neutral-950 text-ink-3 hover:border-[#a3e635] transition-colors border border-line"
          >
            Landing ↗
          </Link>
        </div>
        <nav className="flex-1 overflow-y-auto px-3 py-3" aria-label="Primary">
          {NAV.map((g) => (
            <div key={g.group} className="mt-3 first:mt-1">
              <div className="px-2.5 pb-1.5 text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-3">{g.group}</div>
              <div className="space-y-1">
                {g.items.map(({ to, label, icon: Icon, badge: b }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 rounded-xl px-3 py-2 text-xs transition-all ${
                        isActive
                          ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-950 font-semibold shadow-sm"
                          : "text-ink-2 hover:bg-surface-2 hover:text-ink font-medium"
                      }`
                    }
                  >
                    <Icon size={15} aria-hidden />
                    <span className="flex-1">{label}</span>
                    {b && badge[b] > 0 && (
                      <span className="rounded-full bg-rose-500 px-2 py-0.5 text-[10px] font-bold text-white tabular-nums">
                        {badge[b]}
                      </span>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="space-y-2 border-t border-line p-3.5 text-xs text-ink-3 bg-surface-2/40">
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
        <header className="sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-line bg-bg/85 px-5 py-3 backdrop-blur-md">
          <div className="flex items-center gap-2 text-ink-2 md:hidden">
            <ShieldCheck size={18} className="text-[#65a30d] dark:text-[#a3e635]" aria-hidden />
            <span className="font-bold text-sm text-ink">AgentShield</span>
          </div>
          <div className="hidden items-center gap-2.5 text-xs text-ink-3 md:flex">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#a3e635] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#65a30d] dark:bg-[#a3e635]" />
            </span>
            <span className="font-mono text-[11px] text-ink-2">
              {overview.isError
                ? "Reconnecting to shield engine..."
                : "Connected: Zero-trust intent verification live"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Link
              to="/"
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold text-ink-2 hover:text-ink border border-line bg-surface hover:bg-surface-2 transition-colors shadow-sm"
            >
              Aim True (Landing)
            </Link>
            <Button variant="primary" title="Runs a scripted attack so you can see the shield respond" onClick={() => demo.mutate()} loading={demo.isPending}>
              <Play size={14} aria-hidden /> Watch demo attack
            </Button>
            <Button variant="ghost" onClick={toggle} aria-label="Toggle theme">
              {isDark ? <Sun size={16} /> : <Moon size={16} />}
            </Button>
          </div>
        </header>
        <nav className="flex gap-1.5 overflow-x-auto border-b border-line bg-surface/90 px-3 py-2 md:hidden backdrop-blur" aria-label="Primary (mobile)">
          {NAV.flatMap((g) => g.items).map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end
              className={({ isActive }) =>
                `flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
                  isActive ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-950 font-semibold" : "text-ink-2 hover:bg-surface-2"
                }`
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
