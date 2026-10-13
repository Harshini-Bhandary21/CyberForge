import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Link2, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/client";
import type { ComplianceReport, ControlResult } from "@/api/types";
import { download } from "@/lib/format";
import { Badge, Button, Card, Empty, ErrorNote, Loading, Mono, PageHeader, Stat, StatusPill } from "@/components/ui";

type Filter = "all" | ControlResult["status"];
const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "satisfied", label: "Satisfied" },
  { id: "partial", label: "Partial" },
  { id: "gap", label: "Gap" },
];
const FRAMEWORK_ORDER = ["OWASP LLM Top 10", "NIST AI RMF", "EU AI Act", "ISO/IEC 27001"];

function ControlRow({ c }: { c: ControlResult }) {
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Mono>{c.id}</Mono>
        <span className="font-medium">{c.title}</span>
        <span className="ml-auto">
          <StatusPill status={c.status} />
        </span>
      </div>
      <p className="mt-1 text-xs text-ink-3">Requirement: {c.requirement}</p>
      <p className="mt-2 text-ink-2">{c.evidence}</p>
      {c.citations.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <span
            className="inline-flex items-center gap-1 text-xs text-ink-3"
            title="Each citation points to an entry in the hash-chained audit log, so the evidence can be independently verified."
          >
            <Link2 size={12} aria-hidden /> Evidence:
          </span>
          {c.citations.map((ref) => (
            <span key={ref} title={`Audit log entry ${ref} (hash-chained, tamper-evident)`}>
              <Mono>{ref}</Mono>
            </span>
          ))}
        </div>
      )}
      {c.recommendation && (
        <p className="mt-2 rounded-lg bg-surface-2 px-3 py-2 text-xs text-ink-2">
          <strong className="font-medium text-ink">Recommendation:</strong> {c.recommendation}
        </p>
      )}
    </li>
  );
}

export default function Compliance() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<Filter>("all");
  const q = useQuery({ queryKey: ["compliance"], queryFn: () => api.get<ComplianceReport>("/compliance/report") });
  const md = useMutation({
    mutationFn: async () => {
      const text = await api.get<string>("/compliance/report.md");
      download("agentshield-compliance-report.md", text);
    },
  });

  const actions = (
    <>
      <Button onClick={() => md.mutate()} loading={md.isPending}>
        <Download size={14} aria-hidden /> Download Markdown report
      </Button>
      <Button onClick={() => qc.invalidateQueries({ queryKey: ["compliance"] })} loading={q.isFetching}>
        <RefreshCw size={14} aria-hidden /> Refresh
      </Button>
    </>
  );
  const header = (
    <PageHeader
      title="Compliance: Evidence Autopilot"
      subtitle="Controls from major AI-security frameworks are checked automatically against what the shield actually recorded, and each claim cites the audit-log entries that prove it."
      actions={actions}
    />
  );

  if (q.isPending) return <>{header}<Loading /></>;
  if (q.isError) return <>{header}<ErrorNote error={q.error} /></>;
  const r = q.data;
  const total = r.totals.satisfied + r.totals.partial + r.totals.gap;
  const noEvidence = r.chain.length === 0 || r.controls.every((c) => c.citations.length === 0);

  const frameworks = [...new Set(r.controls.map((c) => c.framework))].sort(
    (a, b) => (FRAMEWORK_ORDER.indexOf(a) + 100) % 100 - (FRAMEWORK_ORDER.indexOf(b) + 100) % 100,
  );

  return (
    <>
      {header}
      {md.isError && <div className="mb-4"><ErrorNote error={md.error} /></div>}

      <div role="note" className="mb-4 flex items-start gap-2 rounded-xl border border-line bg-[var(--warn-bg)] p-3 text-sm">
        <TriangleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-hidden />
        <p><strong>Important: </strong>{r.disclaimer}</p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Control coverage" value={<span className="text-3xl">{r.coverage_pct.toFixed(0)}%</span>} hint={`${total} controls assessed`} icon={ShieldCheck} />
        <Stat label="Satisfied / Partial / Gap" value={<span>{r.totals.satisfied} / {r.totals.partial} / {r.totals.gap}</span>} hint="Evidence-backed status" />
        <Stat
          label="Audit-chain integrity"
          value={
            r.chain.valid ? (
              <Badge tone="good" icon={ShieldCheck}>Intact</Badge>
            ) : (
              <Badge tone="critical" icon={TriangleAlert}>BROKEN</Badge>
            )
          }
          hint={r.chain.valid ? `${r.chain.length} events verified` : `${r.chain.length} events; broken at #${r.chain.broken_at ?? "?"}`}
        />
        <Stat label="Report generated" value={<span className="text-base">{new Date(r.generated_at * 1000).toLocaleTimeString()}</span>} hint={new Date(r.generated_at * 1000).toLocaleDateString()} />
      </div>

      {noEvidence && (
        <Card className="mt-4">
          <Empty
            title="Little evidence recorded yet"
            hint="Controls are scored from real shield activity. Use the Run demo scenario button in the top bar to generate sessions, blocked attacks and a red-team run, then press Refresh."
          />
        </Card>
      )}

      <div className="mt-6 flex flex-wrap items-center gap-2" role="group" aria-label="Filter controls by status">
        {FILTERS.map((f) => {
          const count = f.id === "all" ? total : r.totals[f.id];
          const on = filter === f.id;
          return (
            <button
              key={f.id}
              type="button"
              aria-pressed={on}
              onClick={() => setFilter(f.id)}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition ${on ? "border-accent bg-accent text-white" : "border-line bg-surface hover:bg-surface-2"}`}
            >
              {f.label} <span className="tabular-nums opacity-80">({count})</span>
            </button>
          );
        })}
      </div>

      <div className="mt-4 space-y-4">
        {frameworks.map((fw) => {
          const all = r.controls.filter((c) => c.framework === fw);
          const shown = all.filter((c) => filter === "all" || c.status === filter);
          if (shown.length === 0) return null;
          const sat = all.filter((c) => c.status === "satisfied").length;
          return (
            <Card key={fw} title={fw} pad={false} action={<span className="text-xs text-ink-3">{sat}/{all.length} satisfied</span>}>
              <ul className="divide-y divide-line">
                {shown.map((c) => <ControlRow key={c.id} c={c} />)}
              </ul>
            </Card>
          );
        })}
        {r.controls.every((c) => filter !== "all" && c.status !== filter) && (
          <Card><Empty title="No controls match this filter" /></Card>
        )}
      </div>
    </>
  );
}
