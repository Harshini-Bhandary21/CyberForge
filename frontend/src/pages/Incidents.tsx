import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Activity, Check, CheckCircle2, Mail, Play, ShieldAlert, Siren, Wrench, type LucideIcon } from "lucide-react";
import { api } from "@/api/client";
import type { DemoStep, Incident, TimelineEntry } from "@/api/types";
import { Badge, Button, Card, Empty, ErrorNote, Loading, Tag, PageHeader, SeverityBadge } from "@/components/ui";
import { clock, timeAgo, titleCase } from "@/lib/format";

const KIND_ICON: Record<TimelineEntry["kind"], { icon: LucideIcon; label: string }> = {
  context: { icon: Mail, label: "Context" },
  decision: { icon: ShieldAlert, label: "Decision" },
  anomaly: { icon: Activity, label: "Anomaly" },
  action: { icon: Wrench, label: "Action" },
};

function StatusBadge({ status }: { status: Incident["status"] }) {
  if (status === "resolved")
    return (
      <Badge tone="good" icon={CheckCircle2}>
        Resolved
      </Badge>
    );
  if (status === "contained") return <Badge tone="info" icon={ShieldAlert}>Contained</Badge>;
  return (
    <Badge tone="critical" icon={Siren}>
      Open
    </Badge>
  );
}

function Detail({ inc }: { inc: Incident }) {
  const qc = useQueryClient();
  const done = () => {
    qc.invalidateQueries({ queryKey: ["incidents"] });
    qc.invalidateQueries({ queryKey: ["overview"] });
    qc.invalidateQueries({ queryKey: ["agents"] });
  };
  const apply = useMutation({
    mutationFn: (actionId: string) => api.post<Incident>(`/incidents/${inc.id}/actions/${actionId}`),
    onSuccess: done,
  });
  const resolve = useMutation({ mutationFn: () => api.post<Incident>(`/incidents/${inc.id}/resolve`), onSuccess: done });
  const timeline = [...inc.timeline].sort((a, b) => a.ts - b.ts);

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-lg font-semibold">{inc.title}</h2>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={inc.severity} />
              <span className="text-sm font-medium tabular-nums">Score {inc.score}/100</span>
              <StatusBadge status={inc.status} />
              <span className="text-xs text-ink-3">
                Agent {inc.agent_id} · opened {timeAgo(inc.created_at)}
              </span>
            </div>
          </div>
          <Button onClick={() => resolve.mutate()} loading={resolve.isPending} disabled={inc.status === "resolved"}>
            <Check size={14} aria-hidden /> {inc.status === "resolved" ? "Resolved" : "Mark resolved"}
          </Button>
        </div>
        {resolve.isError && (
          <div className="mt-2">
            <ErrorNote error={resolve.error} />
          </div>
        )}
        <h3 className="mt-4 text-xs font-semibold uppercase tracking-wide text-ink-3">What happened</h3>
        <p className="mt-1 whitespace-pre-line text-sm leading-relaxed">{inc.narrative}</p>
      </Card>

      <Card title="Key facts">
        <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
          <div className="sm:col-span-2">
            <dt className="text-xs text-ink-3">Agent goal</dt>
            <dd>{inc.goal}</dd>
          </div>
          <div>
            <dt className="text-xs text-ink-3">Hostile sources</dt>
            <dd className="mt-0.5 flex flex-wrap gap-1">
              {inc.hostile_sources.length ? inc.hostile_sources.map((s) => <Tag key={s}>{s}</Tag>) : <span className="text-ink-2">None</span>}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-ink-3">Blocked tools</dt>
            <dd className="mt-0.5 flex flex-wrap gap-1">
              {inc.blocked_tools.length ? inc.blocked_tools.map((s) => <Tag key={s}>{s}</Tag>) : <span className="text-ink-2">None</span>}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-ink-3">Counts</dt>
            <dd>
              {inc.blocked} blocked · {inc.approvals} held for approval
            </dd>
          </div>
          <div>
            <dt className="text-xs text-ink-3">Signals</dt>
            <dd>
              {inc.secrets_seen ? "Secrets seen in context" : "No secrets seen"} · peak anomaly {inc.max_anomaly.toFixed(2)}
            </dd>
          </div>
        </dl>
      </Card>

      <Card title="Timeline">
        {timeline.length === 0 ? (
          <p className="text-sm text-ink-2">No events recorded.</p>
        ) : (
          <ol className="relative ml-3 border-l border-line">
            {timeline.map((t, i) => {
              const k = KIND_ICON[t.kind];
              const Icon = k.icon;
              return (
                <li key={i} className="mb-4 ml-5 last:mb-0">
                  <span className="absolute -left-3 flex h-6 w-6 items-center justify-center rounded-full border border-line bg-surface">
                    <Icon size={13} className="text-ink-2" aria-hidden />
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="sr-only">{k.label}: </span>
                    <span className="text-sm font-medium">{t.title}</span>
                    <SeverityBadge severity={t.severity} />
                    <time className="text-xs text-ink-3">{clock(t.ts)}</time>
                  </div>
                  <p className="mt-0.5 break-words text-sm text-ink-2">{t.detail}</p>
                </li>
              );
            })}
          </ol>
        )}
      </Card>

      <Card title="Response plan">
        {inc.actions.length === 0 ? (
          <p className="text-sm text-ink-2">No response actions proposed.</p>
        ) : (
          <ul className="space-y-3">
            {inc.actions.map((a) => (
              <li key={a.id} className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-line p-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{titleCase(a.action)}</span>
                    <Tag>{a.target}</Tag>
                    <Badge tone={a.mode === "executed" ? "info" : "neutral"}>{a.mode === "executed" ? "Executes for real" : "Simulated"}</Badge>
                    <Badge>{a.reversible ? "Reversible" : "Not reversible"}</Badge>
                  </div>
                  <p className="mt-1 text-sm text-ink-2">{a.rationale}</p>
                </div>
                {a.status === "applied" ? (
                  <Badge tone="good" icon={CheckCircle2}>
                    Applied{a.applied_at ? ` ${clock(a.applied_at)}` : ""}
                  </Badge>
                ) : (
                  <Button onClick={() => apply.mutate(a.id)} loading={apply.isPending && apply.variables === a.id} disabled={apply.isPending}>
                    Apply
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {apply.isError && (
          <div className="mt-2">
            <ErrorNote error={apply.error} />
          </div>
        )}
      </Card>
    </div>
  );
}

export default function Incidents() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["incidents"], queryFn: () => api.get<Incident[]>("/incidents"), refetchInterval: 5_000 });
  const [sel, setSel] = useState<string | null>(null);
  const demo = useMutation({
    mutationFn: () => api.post<{ steps: DemoStep[] }>("/demo/run"),
    onSuccess: () => qc.invalidateQueries(),
  });

  const list = q.data ?? [];
  const current = list.find((i) => i.id === sel) ?? list[0] ?? null;

  return (
    <>
      <PageHeader title="Incidents" subtitle="When the shield blocks an attack or holds a dangerous action, it opens an incident with a plain-language story and a response plan." />
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorNote error={q.error} />
      ) : list.length === 0 ? (
        <Card>
          <Empty
            title="No incidents"
            hint={
              <>
                Incidents appear when the shield blocks something. Trigger one from <Link to="/guard" className="text-accent underline">Live Guard</Link> or run the demo scenario.
              </>
            }
            action={
              <Button variant="primary" onClick={() => demo.mutate()} loading={demo.isPending}>
                <Play size={14} aria-hidden /> Run demo scenario
              </Button>
            }
          />
          {demo.isError && <ErrorNote error={demo.error} />}
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(280px,360px)_1fr]">
          <nav aria-label="Incidents" className="min-w-0">
            <ul className="space-y-2">
              {list.map((i) => {
                const active = current?.id === i.id;
                return (
                  <li key={i.id}>
                    <button
                      type="button"
                      aria-current={active ? "true" : undefined}
                      onClick={() => setSel(i.id)}
                      className={`w-full rounded-xl border p-3 text-left transition hover:bg-surface-2 ${active ? "border-accent bg-surface-2" : "border-line bg-surface"}`}
                    >
                      <p className="text-sm font-medium">{i.title}</p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={i.severity} />
                        <span className="text-xs tabular-nums text-ink-2">{i.score}/100</span>
                        <StatusBadge status={i.status} />
                      </div>
                      <p className="mt-1.5 text-xs text-ink-3">
                        {i.agent_id} · {timeAgo(i.created_at)}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          </nav>
          <div className="min-w-0">{current && <Detail key={current.id} inc={current} />}</div>
        </div>
      )}
    </>
  );
}
