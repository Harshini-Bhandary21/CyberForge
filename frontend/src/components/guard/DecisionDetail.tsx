import { Activity, Bot, GitBranch, Link2, ShieldQuestion } from "lucide-react";
import { Link } from "react-router-dom";
import type { GuardDecision } from "@/api/types";
import { Badge, JsonBlock, Mono, SeverityBadge, TrustBadge, VerdictBadge } from "@/components/ui";
import { clock, pct, titleCase } from "@/lib/format";

const VIA: Record<string, string> = {
  control_arg: "chose a control argument (who/where/what)",
  data_arg: "appears in a data argument",
  declared: "declared by the agent",
};

function Section({ title, icon: Icon, children }: { title: string; icon: typeof Bot; children: React.ReactNode }) {
  return (
    <section className="mt-4">
      <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-ink-3">
        <Icon size={13} aria-hidden /> {title}
      </h3>
      {children}
    </section>
  );
}

export function DecisionDetail({ d }: { d: GuardDecision }) {
  const v = d.verifier;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={d.verdict} />
        <SeverityBadge severity={d.risk} />
        <span className="text-xs text-ink-2">Risk: {d.risk}</span>
        <span className="text-xs text-ink-3">Latency {d.latency_ms.toFixed(1)} ms</span>
        <span className="text-xs text-ink-3">{clock(d.created_at)}</span>
      </div>
      <p className="mt-2 text-sm">
        Agent <Mono>{d.agent_id}</Mono> called <Mono>{d.tool}</Mono>
      </p>
      <div className="mt-2">
        <JsonBlock value={d.args} />
      </div>

      <Section title={`Findings (${d.findings.length})`} icon={ShieldQuestion}>
        {d.findings.length === 0 ? (
          <p className="text-sm text-ink-2">No rules fired.</p>
        ) : (
          <ul className="space-y-2">
            {d.findings.map((f, i) => (
              <li key={`${f.rule}-${i}`} className="rounded-lg border border-line p-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <Mono>{f.rule}</Mono>
                  <SeverityBadge severity={f.severity} />
                  <VerdictBadge verdict={f.verdict} />
                </div>
                <p className="mt-1 text-sm">{f.message}</p>
                {f.evidence.length > 0 && (
                  <ul className="mt-1 list-disc pl-5 text-xs text-ink-2">
                    {f.evidence.map((e, j) => (
                      <li key={j} className="break-words">
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Taint trace" icon={GitBranch}>
        {d.taint.sources.length === 0 ? (
          <p className="text-sm text-ink-2">
            {d.taint.tainted ? "Tainted, but no specific source was matched." : "No argument values trace back to untrusted context."}
          </p>
        ) : (
          <ul className="space-y-2">
            {d.taint.sources.map((s, i) => (
              <li key={`${s.item_id}-${i}`} className="rounded-lg border border-line p-2.5 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Mono>{s.source}</Mono>
                  <TrustBadge trust={s.trust} />
                </div>
                <p className="mt-1 text-xs text-ink-2">
                  Source {VIA[s.via] ?? s.via}
                  {s.matched.length > 0 && ": "}
                  {s.matched.map((m, j) => (
                    <span key={j} className="mr-1">
                      <Mono>{m}</Mono>
                    </span>
                  ))}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Intent verifier" icon={Bot}>
        {v ? (
          <div className="rounded-lg border border-line p-2.5 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={v.aligned === "yes" ? "good" : v.aligned === "no" ? "critical" : "warn"}>
                {v.aligned === "yes" ? "Aligned with goal" : v.aligned === "no" ? "Not aligned with goal" : "Alignment uncertain"}
              </Badge>
              <span className="text-xs text-ink-2">Confidence {pct(v.confidence)}</span>
              <Badge>{v.engine === "llm" ? `LLM judge${v.provider ? ` · ${v.provider}` : ""}` : "Heuristic engine"}</Badge>
            </div>
            <p className="mt-1 text-ink-2">{v.reasoning}</p>
          </div>
        ) : (
          <p className="text-sm text-ink-2">Verifier not consulted for this call.</p>
        )}
      </Section>

      {d.anomalies.length > 0 && (
        <Section title="Behavioural anomalies" icon={Activity}>
          <ul className="space-y-1.5">
            {d.anomalies.map((a, i) => (
              <li key={i} className="text-sm">
                <Badge tone="warn">{titleCase(a.kind)}</Badge> <span className="text-xs text-ink-3">score {a.score.toFixed(2)}</span>
                <p className="text-ink-2">{a.detail}</p>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {(d.approval_id || d.incident_id) && (
        <Section title="Follow-up" icon={Link2}>
          <ul className="space-y-1 text-sm">
            {d.approval_id && (
              <li>
                Held for human approval. <Link to="/approvals" className="text-accent underline">Open approvals queue</Link> (<Mono>{d.approval_id}</Mono>)
              </li>
            )}
            {d.incident_id && (
              <li>
                Incident opened. <Link to="/incidents" className="text-accent underline">View incidents</Link> (<Mono>{d.incident_id}</Mono>)
              </li>
            )}
          </ul>
        </Section>
      )}
    </div>
  );
}
