import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Check, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { api } from "@/api/client";
import type { Approval } from "@/api/types";
import { Badge, Button, Card, Empty, ErrorNote, Field, inputClass, JsonBlock, Loading, Mono, PageHeader, SeverityBadge } from "@/components/ui";
import { timeAgo } from "@/lib/format";

type Tab = "pending" | "resolved" | "all";

function PendingCard({ a, reviewer }: { a: Approval; reviewer: string }) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const resolve = useMutation({
    mutationFn: (approve: boolean) =>
      api.post<Approval>(`/approvals/${a.id}/resolve`, { approve, reviewer: reviewer.trim() || "analyst", note: note.trim() || null }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
      qc.invalidateQueries({ queryKey: ["decisions"] });
    },
  });
  return (
    <li className="rounded-xl border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Mono>{a.tool}</Mono>
        <SeverityBadge severity={a.risk} />
        <Badge tone="warn">Pending review</Badge>
        <span className="text-xs text-ink-3">
          Agent {a.agent_id} · requested {timeAgo(a.created_at)}
        </span>
      </div>
      <div className="mt-3 grid gap-4 lg:grid-cols-2">
        <div className="min-w-0">
          <p className="mb-1 text-xs font-medium text-ink-2">Exact arguments</p>
          <JsonBlock value={a.args} />
        </div>
        <div className="min-w-0">
          <p className="mb-1 text-xs font-medium text-ink-2">Why it was held</p>
          {a.reasons.length === 0 ? (
            <p className="text-sm text-ink-2">No reasons recorded.</p>
          ) : (
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {a.reasons.map((r, i) => (
                <li key={i} className="break-words">
                  {r}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <div className="min-w-48 flex-1">
          <Field label="Note (optional)">
            <input className={inputClass} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Reason for your decision" />
          </Field>
        </div>
        <Button variant="primary" onClick={() => resolve.mutate(true)} loading={resolve.isPending && resolve.variables === true} disabled={resolve.isPending}>
          <Check size={14} aria-hidden /> Approve
        </Button>
        <Button variant="danger" onClick={() => resolve.mutate(false)} loading={resolve.isPending && resolve.variables === false} disabled={resolve.isPending}>
          <X size={14} aria-hidden /> Deny
        </Button>
      </div>
      {resolve.isError && (
        <div className="mt-2">
          <ErrorNote error={resolve.error} />
        </div>
      )}
    </li>
  );
}

function ResolvedRow({ a }: { a: Approval }) {
  const ok = a.status === "approved";
  return (
    <li className="rounded-xl border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Mono>{a.tool}</Mono>
        <SeverityBadge severity={a.risk} />
        {ok ? (
          <Badge tone="good" icon={CheckCircle2}>
            Approved
          </Badge>
        ) : (
          <Badge tone="critical" icon={XCircle}>
            Denied
          </Badge>
        )}
        <span className="text-xs text-ink-3">
          Agent {a.agent_id} · by {a.reviewer ?? "unknown"}
          {a.resolved_at ? ` · ${timeAgo(a.resolved_at)}` : ""}
        </span>
      </div>
      {a.note && <p className="mt-2 text-sm">Note: {a.note}</p>}
      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-ink-2">Arguments and reasons</summary>
        <div className="mt-2">
          <JsonBlock value={a.args} />
          {a.reasons.length > 0 && (
            <ul className="mt-2 list-disc pl-5 text-sm">
              {a.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}
        </div>
      </details>
    </li>
  );
}

export default function Approvals() {
  const q = useQuery({ queryKey: ["approvals"], queryFn: () => api.get<Approval[]>("/approvals"), refetchInterval: 4_000 });
  const [tab, setTab] = useState<Tab>("pending");
  const [reviewer, setReviewer] = useState("analyst");

  const all = q.data ?? [];
  const pending = all.filter((a) => a.status === "pending");
  const resolved = all.filter((a) => a.status !== "pending");
  const shown = tab === "pending" ? pending : tab === "resolved" ? resolved : all;
  const tabs: { id: Tab; label: string; n: number }[] = [
    { id: "pending", label: "Pending", n: pending.length },
    { id: "resolved", label: "Resolved", n: resolved.length },
    { id: "all", label: "All", n: all.length },
  ];

  return (
    <>
      <PageHeader
        title="Approvals"
        subtitle="Risky but plausible actions are held here until a human decides."
        actions={
          <div className="w-44">
            <Field label="Reviewer name">
              <input className={inputClass} value={reviewer} onChange={(e) => setReviewer(e.target.value)} />
            </Field>
          </div>
        }
      />
      <div className="mb-4 flex items-start gap-2 rounded-lg bg-[var(--info-bg)] p-3 text-sm">
        <Info size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden />
        <p>
          An approval is bound to the exact arguments shown. If the agent changes any value, the call is judged again and needs a new approval. Blocked actions can never be approved.
        </p>
      </div>

      <div role="tablist" aria-label="Approval status" className="mb-4 flex flex-wrap gap-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`rounded-lg px-3 py-1.5 text-sm font-medium ${tab === t.id ? "bg-accent text-white" : "border border-line bg-surface hover:bg-surface-2"}`}
          >
            {t.label} <span className="tabular-nums opacity-80">({t.n})</span>
          </button>
        ))}
      </div>

      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorNote error={q.error} />
      ) : shown.length === 0 ? (
        <Card>
          <Empty
            title={tab === "pending" ? "Nothing waiting for review" : "No approvals here yet"}
            hint="When the shield judges a call risky but plausible, it appears here. Try the Fraud or Legit scenarios in Live Guard."
          />
        </Card>
      ) : (
        <ul className="space-y-3">
          {shown.map((a) => (a.status === "pending" ? <PendingCard key={a.id} a={a} reviewer={reviewer} /> : <ResolvedRow key={a.id} a={a} />))}
        </ul>
      )}
    </>
  );
}
