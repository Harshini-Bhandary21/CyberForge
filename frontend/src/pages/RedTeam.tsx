import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Play, ShieldAlert, Table2, BarChart3 } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "@/api/client";
import type { RedTeamRun } from "@/api/types";
import { BarCompare, type BarRow } from "@/components/charts/BarCompare";
import { Badge, Button, Card, Empty, ErrorNote, Field, inputClass, Loading, Mono, PageHeader, Stat } from "@/components/ui";
import { pct, titleCase } from "@/lib/format";

const CONFIG_LABEL: Record<string, string> = {
  full_shield: "Full shield",
  no_capabilities: "Without capability tokens",
  no_taint_tracking: "Without taint tracking",
  no_intent_verifier: "Without intent verifier",
  capabilities_only: "Capabilities only",
};
const CONFIG_NOTE: Record<string, string> = {
  full_shield: "All layers on: the reference configuration.",
  no_capabilities: "Removes least-privilege tool tokens; shows how much capability scoping contributes.",
  no_taint_tracking: "Removes provenance tracking; untrusted content can steer actions unnoticed.",
  no_intent_verifier: "Removes goal-alignment checks; off-task actions are no longer questioned.",
  capabilities_only: "Only capability tokens active: a baseline for what layering adds.",
};
const RULES: Record<string, string> = {
  "R-CAP-001": "Capability: the tool was not granted to this session",
  "R-TAINT-001": "Provenance: untrusted content controls a sensitive argument",
  "R-TAINT-002": "Provenance: hostile content reached a high-risk action",
  "R-TAINT-004": "Provenance: data derived from untrusted sources flows to an external sink",
  "R-INTENT-001": "Intent: action does not serve the user's stated goal",
  "R-DLP-001": "Data loss: secrets or sensitive data leaving the boundary",
  "R-FRAUD-001": "Fraud: payment or transfer matched fraud signals",
};

function ChartOrTable({ rows, aLabel, bLabel, extra }: { rows: BarRow[]; aLabel: string; bLabel?: string; extra?: { head: string; cells: string[] } }) {
  const [table, setTable] = useState(false);
  return (
    <div>
      <div className="mb-2 flex justify-end">
        <button type="button" aria-pressed={table} onClick={() => setTable((t) => !t)} className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-ink-2 hover:bg-surface-2">
          {table ? <BarChart3 size={13} aria-hidden /> : <Table2 size={13} aria-hidden />}
          {table ? "Show as chart" : "Show as table"}
        </button>
      </div>
      {table ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-ink-3">
              <tr>
                <th className="py-1 pr-3 font-medium">Name</th>
                <th className="py-1 pr-3 text-right font-medium">{aLabel}</th>
                {bLabel && <th className="py-1 pr-3 text-right font-medium">{bLabel}</th>}
                {extra && <th className="py-1 pr-3 text-right font-medium">{extra.head}</th>}
                <th className="py-1 text-right font-medium">Cases</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line tabular-nums">
              {rows.map((r, i) => (
                <tr key={r.label}>
                  <td className="py-1.5 pr-3">{r.label}</td>
                  <td className="py-1.5 pr-3 text-right">{pct(r.a, 1)}</td>
                  {bLabel && <td className="py-1.5 pr-3 text-right">{pct(r.b ?? 0, 1)}</td>}
                  {extra && <td className="py-1.5 pr-3 text-right">{extra.cells[i]}</td>}
                  <td className="py-1.5 text-right">{r.n ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <BarCompare rows={rows} aLabel={aLabel} bLabel={bLabel} labelWidth={170} />
      )}
    </div>
  );
}

function Results({ run }: { run: RedTeamRun }) {
  const s = run.summary;
  const cat: BarRow[] = run.by_category.map((c) => ({ label: titleCase(c.category), a: c.baseline, b: c.protected, n: c.n }));
  const mut: BarRow[] = run.by_mutator.map((c) => ({ label: titleCase(c.mutator), a: c.baseline, b: c.protected, n: c.n }));
  const abl: BarRow[] = run.ablations.map((a) => ({ label: CONFIG_LABEL[a.config] ?? titleCase(a.config), a: a.asr }));
  const full = run.ablations.find((a) => a.config === "full_shield");
  const rules = Object.entries(run.defended_by_rule).sort((a, b) => b[1] - a[1]);
  const maxRule = Math.max(1, ...rules.map(([, n]) => n));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="col-span-2 rounded-xl border border-line bg-surface p-4">
          <div className="text-xs font-medium text-ink-3">Attack success rate</div>
          <div className="mt-1 flex flex-wrap items-baseline gap-2 tabular-nums">
            <span className="text-2xl font-semibold" title="Unprotected agent">{pct(s.asr_baseline, 1)}</span>
            <span aria-hidden className="text-ink-3">→</span>
            <span className="text-2xl font-semibold text-good" title="With AgentShield">{pct(s.asr_protected, 1)}</span>
          </div>
          <div className="mt-0.5 text-xs text-ink-3">Without shield → with shield. Lower is better.</div>
        </div>
        <Stat label="Resistance score" value={s.resistance_score.toFixed(0)} hint="Share of attack success removed" />
        <Stat label="False-block rate" value={pct(s.false_block_rate, 1)} hint="Legitimate actions wrongly blocked" />
        <Stat label="Approval friction" value={pct(s.friction_rate, 1)} hint="Legitimate actions held for review" />
        <Stat label="Avg latency" value={`${s.avg_latency_ms.toFixed(1)} ms`} hint="Per guarded tool call" icon={Activity} />
        <Stat label="p95 latency" value={`${s.p95_latency_ms.toFixed(1)} ms`} hint="95th percentile" />
        <div className="col-span-2 rounded-xl border border-line bg-surface p-4 text-xs text-ink-2">
          <div className="mb-1 font-medium text-ink-3">Run parameters</div>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            <span>Cases: <Mono>{run.params.cases}</Mono></span>
            <span>Seed: <Mono>{run.params.seed}</Mono></span>
            <span>Engine: <Mono>{run.params.engine}</Mono></span>
            <span>Payloads: <Mono>{run.params.payloads}</Mono></span>
            <span>Evasions: <Mono>{run.params.mutators.length}</Mono></span>
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="By attack category">
          <ChartOrTable rows={cat} aLabel="Unprotected agent" bLabel="With AgentShield" />
        </Card>
        <Card title="By evasion technique">
          <ChartOrTable rows={mut} aLabel="Unprotected agent" bLabel="With AgentShield" />
        </Card>
      </div>

      <Card title="Defence layers (ablation)">
        <p className="mb-3 text-sm text-ink-2">
          Each row switches one defence off and re-runs the same attacks. The further a bar rises above Full shield, the more that layer was contributing.
          {full && <> Full shield lets {pct(full.asr, 1)} through.</>}
        </p>
        <ChartOrTable rows={abl} aLabel="Attack success rate" extra={{ head: "False-block rate", cells: run.ablations.map((a) => pct(a.false_block_rate, 1)) }} />
        <ul className="mt-3 grid gap-1 text-xs text-ink-3 sm:grid-cols-2">
          {run.ablations.map((a) => (
            <li key={a.config}><span className="font-medium text-ink-2">{CONFIG_LABEL[a.config] ?? titleCase(a.config)}</span>: {CONFIG_NOTE[a.config] ?? ""} False blocks {pct(a.false_block_rate, 1)}.</li>
          ))}
        </ul>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Which rules stopped attacks">
          {rules.length === 0 ? (
            <Empty title="No rule data" />
          ) : (
            <ul className="space-y-2.5">
              {rules.map(([id, n]) => (
                <li key={id} title={`${id}: ${n} attacks stopped`}>
                  <div className="flex items-baseline justify-between gap-2 text-xs">
                    <span><Mono>{id}</Mono> <span className="text-ink-2">{RULES[id] ?? "Other rule"}</span></span>
                    <span className="tabular-nums text-ink">{n}</span>
                  </div>
                  <div className="mt-1 h-1.5 rounded-full bg-surface-2" aria-hidden>
                    <div className="h-full rounded-full bg-series-1" style={{ width: `${(n / maxRule) * 100}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Known limitations and breaches" action={<Badge tone={run.breaches.length ? "warn" : "good"} icon={ShieldAlert}>{run.breaches.length} breach{run.breaches.length === 1 ? "" : "es"}</Badge>}>
          <p className="text-sm text-ink-2">
            The attacks that still succeed are semantic manipulation through an authorised channel, for example persuading the agent to relay false text to an allowed recipient.
            Action-level controls judge what an agent does, not whether the words it sends are true, so they cannot stop these.
          </p>
          <p className="mt-2 text-sm text-ink-2">
            The attack corpus is self-authored, so these numbers measure regression between versions, not absolute security.
          </p>
          {run.breaches.length > 0 && (
            <div className="mt-3 max-h-56 overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-ink-3"><tr><th className="py-1 pr-2 font-medium">Payload</th><th className="py-1 pr-2 font-medium">Technique</th><th className="py-1 font-medium">Host</th></tr></thead>
                <tbody className="divide-y divide-line">
                  {run.breaches.map((b, i) => (
                    <tr key={`${b.payload}-${i}`}>
                      <td className="py-1.5 pr-2"><Mono>{b.payload}</Mono></td>
                      <td className="py-1.5 pr-2">{titleCase(b.mutator)}</td>
                      <td className="py-1.5 break-all">{b.host}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

export default function RedTeam() {
  const qc = useQueryClient();
  const [cases, setCases] = useState(200);
  const [seed, setSeed] = useState(7);
  const [cats, setCats] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);

  const runs = useQuery({ queryKey: ["redteam", "runs"], queryFn: () => api.get<RedTeamRun[]>("/redteam/runs") });
  const list = runs.data ?? [];
  const current = list.find((r) => r.id === selected) ?? list[0];

  const known = [...new Set(list.flatMap((r) => r.by_category.map((c) => c.category)))];
  useEffect(() => {
    if (selected && !list.some((r) => r.id === selected)) setSelected(null);
  }, [list, selected]);

  const run = useMutation({
    mutationFn: () => api.post<RedTeamRun>("/redteam/run", { max_cases: cases, seed, ...(cats.length ? { categories: cats } : {}) }),
    onSuccess: (r) => {
      setSelected(r.id);
      qc.invalidateQueries({ queryKey: ["redteam"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });
  const clampCases = (v: number) => setCases(Number.isFinite(v) ? Math.min(1500, Math.max(10, Math.round(v))) : 200);

  return (
    <>
      <PageHeader title="Red Team" subtitle="Automated attack campaigns replay injection, exfiltration and fraud payloads, with evasion techniques applied, against an unprotected agent and then against AgentShield." />

      <Card title="Run a campaign" className="mb-4">
        <form onSubmit={(e) => { e.preventDefault(); run.mutate(); }} className="grid gap-4 md:grid-cols-[2fr_1fr_auto] md:items-end">
          <Field label={`Number of cases: ${cases}`}>
            <div className="flex items-center gap-3">
              <input type="range" min={10} max={1500} step={10} value={cases} onChange={(e) => clampCases(+e.target.value)} className="w-full accent-[var(--accent)]" aria-label="Number of cases (slider)" />
              <input type="number" min={10} max={1500} value={cases} onChange={(e) => clampCases(+e.target.value)} className={`${inputClass} w-24`} aria-label="Number of cases (exact)" />
            </div>
          </Field>
          <Field label="Seed" hint="Same seed, same campaign">
            <input type="number" value={seed} onChange={(e) => setSeed(Number.isFinite(+e.target.value) ? Math.round(+e.target.value) : 7)} className={inputClass} />
          </Field>
          <Button type="submit" variant="primary" loading={run.isPending}>
            <Play size={14} aria-hidden /> {run.isPending ? "Running…" : "Run campaign"}
          </Button>
        </form>
        {known.length > 0 && (
          <fieldset className="mt-4">
            <legend className="mb-1 text-xs font-medium text-ink-2">Attack categories (optional; none selected means all)</legend>
            <div className="flex flex-wrap gap-2">
              {known.map((c) => {
                const on = cats.includes(c);
                return (
                  <label key={c} className={`inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-xs ${on ? "border-accent bg-surface-2 font-medium" : "border-line"}`}>
                    <input type="checkbox" checked={on} onChange={() => setCats(on ? cats.filter((x) => x !== c) : [...cats, c])} className="accent-[var(--accent)]" />
                    {titleCase(c)}
                  </label>
                );
              })}
            </div>
          </fieldset>
        )}
        {run.isPending && <p role="status" className="mt-3 text-sm text-ink-2">Replaying {cases} attack cases against both configurations. This takes a few seconds.</p>}
        {run.isError && <div className="mt-3"><ErrorNote error={run.error} /></div>}
      </Card>

      {runs.isPending ? (
        <Loading />
      ) : runs.isError ? (
        <ErrorNote error={runs.error} />
      ) : !current ? (
        <Card><Empty title="No campaigns yet" hint="Run your first campaign above to measure how well the shield resists attacks." /></Card>
      ) : (
        <>
          {list.length > 1 && (
            <div className="mb-4 max-w-sm">
              <Field label="Viewing run">
                <select className={inputClass} value={current.id} onChange={(e) => setSelected(e.target.value)}>
                  {list.map((r) => (
                    <option key={r.id} value={r.id}>
                      {new Date(r.created_at * 1000).toLocaleString()} · {r.params.cases} cases · seed {r.params.seed}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          )}
          <Results run={current} />
        </>
      )}
    </>
  );
}
