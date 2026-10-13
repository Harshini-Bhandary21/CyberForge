import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Bug, ClipboardCheck, Link2, Play, ShieldCheck, Siren, Swords, UserCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import type { AuditEvent, DemoStep, Overview as OverviewData } from "@/api/types";
import { RiskGauge } from "@/components/charts/RiskGauge";
import { Badge, Button, Card, Empty, ErrorNote, Loading, PageHeader, Stat } from "@/components/ui";
import { clock, humanize, titleCase } from "@/lib/format";

const BREAKDOWN_LABEL: Record<string, string> = {
  open_incidents: "Open incidents",
  pending_approvals: "Pending approvals",
  anomaly_rate: "Behavioural anomalies",
  red_team_exposure: "Red-team exposure",
  compliance_gaps: "Compliance gaps",
};
const BREAKDOWN_MAX: Record<string, number> = {
  open_incidents: 35,
  pending_approvals: 10,
  anomaly_rate: 15,
  red_team_exposure: 25,
  compliance_gaps: 15,
};

export default function Overview() {
  const qc = useQueryClient();
  const ov = useQuery({ queryKey: ["overview"], queryFn: () => api.get<OverviewData>("/overview"), refetchInterval: 5_000 });
  const events = useQuery({ queryKey: ["events", "recent"], queryFn: () => api.get<AuditEvent[]>("/events?limit=12"), refetchInterval: 5_000 });
  const demo = useMutation({
    mutationFn: () => api.post<{ steps: DemoStep[] }>("/demo/run"),
    onSuccess: () => qc.invalidateQueries(),
  });

  if (ov.isPending) return <Loading />;
  if (ov.isError) return <ErrorNote error={ov.error} />;
  const o = ov.data;
  const c = o.counts;
  const empty = c.decisions === 0 && c.sessions === 0;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="One runtime shield between your AI agents and the actions they can take. Every tool call is judged on provenance, intent, data loss and risk, then logged to a tamper-evident audit trail."
      />

      {empty && (
        <Card className="mb-6">
          <Empty
            title="No agent activity yet"
            hint="Run the scripted scenario: a phishing email hijacks an agent, the shield blocks the attack, an incident is opened, and a red-team campaign measures resistance."
            action={
              <Button variant="primary" onClick={() => demo.mutate()} loading={demo.isPending}>
                <Play size={14} aria-hidden /> Run demo scenario
              </Button>
            }
          />
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="AI Risk Score">
          <RiskGauge score={o.risk_score} label={o.risk_label} />
          <ul className="mt-2 space-y-2">
            {Object.entries(o.risk_breakdown).map(([k, v]) => (
              <li key={k}>
                <div className="flex justify-between text-xs text-ink-2">
                  <span>{BREAKDOWN_LABEL[k] ?? titleCase(k)}</span>
                  <span className="tabular-nums">+{v}</span>
                </div>
                <div className="mt-1 h-1.5 rounded-full bg-surface-2" aria-hidden>
                  <div className="h-full rounded-full bg-series-1" style={{ width: `${Math.min(100, (v / (BREAKDOWN_MAX[k] ?? 20)) * 100)}%` }} />
                </div>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-ink-3">Lower is better. Each component is capped so no single signal dominates.</p>
        </Card>

        <div className="space-y-4 lg:col-span-2">
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat label="Tool calls judged" value={c.decisions} hint={`${c.sessions} sessions`} icon={ShieldCheck} />
          <Stat label="Attacks blocked" value={c.blocked} hint={`${c.hostile_context} hostile inputs`} icon={Ban} />
          <Stat label="Held for approval" value={c.pending_approvals} hint={`${c.held_for_approval} total`} icon={UserCheck} />
          <Stat label="Open incidents" value={c.open_incidents} hint={`${c.quarantined_agents} agent(s) quarantined`} icon={Siren} />
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Link to="/redteam" className="block">
            <Stat
              label="Red-team resistance"
              value={o.resistance_score === null ? "—" : `${o.resistance_score}%`}
              hint={o.resistance_score === null ? "Run a campaign" : "Share of attacks stopped"}
              icon={Swords}
            />
          </Link>
          <Link to="/compliance" className="block">
            <Stat label="Compliance coverage" value={`${o.compliance_coverage}%`} hint="Evidence-backed controls" icon={ClipboardCheck} />
          </Link>
          <Stat
            label="Audit chain"
            value={o.audit_chain.valid ? "Intact" : "BROKEN"}
            hint={`${o.audit_chain.length} events, hash-linked`}
            icon={Link2}
          />
        </div>
        </div>
      </div>


      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card title="Live audit trail" className="lg:col-span-2" pad={false} action={<Badge tone="info">auto-refresh 5s</Badge>}>
          {events.data && events.data.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Agent</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {events.data.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap text-ink-3 tabular-nums">{clock(e.ts)}</td>
                    <td className="whitespace-nowrap text-xs">{humanize(e.type)}</td>
                    <td className="text-ink-2">{e.agent_id ?? "—"}</td>
                    <td className="max-w-[320px] truncate text-ink-2">
                      {summarise(e)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty title="Nothing logged yet" />
          )}
        </Card>

        <Card title="How a call is judged">
          <ol className="space-y-3 text-sm text-ink-2">
            {[
              ["Provenance", "Did untrusted content choose the recipient, URL, command or amount?"],
              ["Intent", "An isolated verifier checks the action against the user's goal only."],
              ["Capabilities", "Least-privilege tools derived from the goal."],
              ["Data & fraud", "DLP for secrets and PII; risk scoring for payments."],
              ["Human in the loop", "Critical actions wait for approval. Blocks cannot be overridden."],
            ].map(([t, d], i) => (
              <li key={t} className="flex gap-3">
                <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-surface-2 text-xs font-medium text-ink">{i + 1}</span>
                <span>
                  <b className="text-ink">{t}.</b> {d}
                </span>
              </li>
            ))}
          </ol>
          <div className="mt-4 flex items-center gap-1.5 text-xs text-ink-3">
            <Bug size={13} aria-hidden /> Every step is recorded as evidence for compliance.
          </div>
        </Card>
      </div>
    </>
  );
}

function summarise(e: AuditEvent): string {
  const p = e.payload as Record<string, unknown>;
  switch (e.type) {
    case "guard.decision":
      return `${humanize(String(p.tool))} → ${humanize(String(p.verdict))}`;
    case "context.ingested":
      return `${humanize(String(p.source))} · ${humanize(String(p.trust))} · risk ${Number(p.risk_score ?? 0).toFixed(2)}`;
    case "session.created":
      return String(p.goal ?? "");
    case "anomaly.detected":
      return `${humanize(String(p.kind))}: ${p.detail}`;
    default:
      return "";
  }
}
