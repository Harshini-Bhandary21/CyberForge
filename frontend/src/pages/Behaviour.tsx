import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Ban, CheckCircle2, GraduationCap, ShieldCheck, Undo2 } from "lucide-react";
import { api } from "@/api/client";
import type { AgentInfo, AnomalyEvent } from "@/api/types";
import { Chip } from "@/components/detect/shared";
import { Badge, Button, Card, Empty, ErrorNote, Loading, PageHeader, Mono } from "@/components/ui";
import { clock, timeAgo, titleCase } from "@/lib/format";

const MATURE = 5;

function ToolBars({ tools }: { tools: Record<string, number> }) {
  const rows = Object.entries(tools).sort((a, b) => b[1] - a[1]);
  if (!rows.length) return <p className="text-xs text-ink-3">No allowed tool calls recorded yet.</p>;
  const max = Math.max(...rows.map(([, n]) => n));
  return (
    <ul className="space-y-1.5">
      {rows.slice(0, 8).map(([name, n]) => (
        <li key={name} className="grid grid-cols-[minmax(0,8rem)_1fr_2.5rem] items-center gap-2 text-xs">
          <span className="truncate font-mono" title={name}>{name}</span>
          <div className="h-1.5 rounded-full bg-surface-2" aria-hidden>
            <div className="h-full rounded-full bg-series-1" style={{ width: `${(n / max) * 100}%` }} />
          </div>
          <span className="text-right tabular-nums text-ink-2">{n}</span>
        </li>
      ))}
    </ul>
  );
}

function AgentCard({ a }: { a: AgentInfo }) {
  const qc = useQueryClient();
  const act = useMutation({
    mutationFn: (kind: "quarantine" | "release") => api.post(`/agents/${encodeURIComponent(a.id)}/${kind}`),
    onSuccess: () => qc.invalidateQueries(),
  });
  const b = a.baseline;
  const q = a.status === "quarantined";
  return (
    <Card
      title={<span className="font-mono">{a.id}</span>}
      action={
        q ? (
          <Badge tone="critical" icon={Ban}>Quarantined</Badge>
        ) : (
          <Badge tone="good" icon={CheckCircle2}>Active</Badge>
        )
      }
    >
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {b.mature ? (
          <Badge tone="good" icon={ShieldCheck}>Baseline established</Badge>
        ) : (
          <Badge tone="info" icon={GraduationCap}>Learning {Math.min(b.sessions, MATURE)}/{MATURE} sessions</Badge>
        )}
        <span className="text-ink-3">
          {b.sessions} session{b.sessions === 1 ? "" : "s"} · {b.calls_mean.toFixed(1)} ± {b.calls_std.toFixed(1)} calls/session
        </span>
      </div>
      <h3 className="mb-1.5 mt-4 text-xs font-medium text-ink-2">Tool usage</h3>
      <ToolBars tools={b.tools} />
      <h3 className="mb-1.5 mt-4 text-xs font-medium text-ink-2">Known destinations</h3>
      {b.destinations.length ? (
        <div className="flex flex-wrap gap-1.5">
          {b.destinations.map((d) => (
            <Chip key={d}>{d}</Chip>
          ))}
        </div>
      ) : (
        <p className="text-xs text-ink-3">No egress destinations seen.</p>
      )}
      {(a.revoked_tools.length > 0 || a.blocked_sources.length > 0) && (
        <p className="mt-3 text-xs text-ink-2">
          {a.revoked_tools.length > 0 && <>Revoked tools: {a.revoked_tools.join(", ")}. </>}
          {a.blocked_sources.length > 0 && <>Blocked sources: {a.blocked_sources.join(", ")}.</>}
        </p>
      )}
      <div className="mt-4 flex items-center justify-between gap-2 border-t border-line pt-3">
        <span className="text-xs text-ink-3">Last seen {timeAgo(a.last_seen)}</span>
        {q ? (
          <Button onClick={() => act.mutate("release")} loading={act.isPending}>
            <Undo2 size={14} aria-hidden /> Release
          </Button>
        ) : (
          <Button variant="danger" onClick={() => act.mutate("quarantine")} loading={act.isPending}>
            <Ban size={14} aria-hidden /> Quarantine
          </Button>
        )}
      </div>
      {act.isError && <div className="mt-2"><ErrorNote error={act.error} /></div>}
    </Card>
  );
}

const KINDS = ["new_tool", "new_destination", "call_burst", "data_volume", "off_hours", "repeated_blocks"];

export default function Behaviour() {
  const agents = useQuery({ queryKey: ["agents"], queryFn: () => api.get<AgentInfo[]>("/agents"), refetchInterval: 5000 });
  const anoms = useQuery({ queryKey: ["anomalies", 100], queryFn: () => api.get<AnomalyEvent[]>("/anomalies?limit=100"), refetchInterval: 5000 });

  return (
    <>
      <PageHeader
        title="Agent behaviour & anomalies"
        subtitle="Each agent gets a learned baseline of tools, destinations, volume and hours. Deviations are scored and surfaced here."
      />

      <Card title="How baselines work" className="mb-6">
        <p className="text-ink-2">
          Baselines learn only from <strong className="text-ink">allowed</strong> calls, so an attacker cannot poison them by probing with blocked actions. An agent is considered established after {MATURE} sessions; before that it is still learning and anomaly checks are not applied.
        </p>
        <div className="mt-3 flex flex-wrap gap-1.5" aria-label="Anomaly kinds detected">
          {KINDS.map((k) => (
            <Chip key={k}>{k}</Chip>
          ))}
        </div>
      </Card>

      <h2 className="mb-3 text-sm font-semibold">Agents</h2>
      {agents.isPending && <Loading />}
      {agents.isError && <ErrorNote error={agents.error} />}
      {agents.data && agents.data.length === 0 && (
        <Card>
          <Empty title="No agents observed yet" hint="Agents appear here once they open a session through the shield." />
        </Card>
      )}
      {agents.data && agents.data.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {agents.data.map((a) => (
            <AgentCard key={a.id} a={a} />
          ))}
        </div>
      )}

      <div className="mt-6">
        <Card title={<span className="inline-flex items-center gap-1.5"><Activity size={15} aria-hidden /> Anomalies</span>} pad={false}>
          {anoms.isPending && <Loading />}
          {anoms.isError && <div className="p-4"><ErrorNote error={anoms.error} /></div>}
          {anoms.data && anoms.data.length === 0 && (
            <Empty title="No anomalies detected" hint="Agents are behaving within their learned baselines." />
          )}
          {anoms.data && anoms.data.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Agent</th>
                    <th>Kind</th>
                    <th>Score</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {anoms.data.map((e) => (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap tabular-nums">{clock(e.ts)}</td>
                      <td>{e.agent_id ? <Mono>{e.agent_id}</Mono> : "—"}</td>
                      <td className="whitespace-nowrap">{titleCase(e.kind)}</td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-16 rounded-full bg-surface-2" aria-hidden>
                            <div className="h-full rounded-full bg-series-1" style={{ width: `${Math.min(100, e.score * 100)}%` }} />
                          </div>
                          <span className="tabular-nums">{e.score.toFixed(2)}</span>
                        </div>
                      </td>
                      <td className="min-w-64">{e.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
