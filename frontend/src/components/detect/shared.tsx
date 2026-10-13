import type { Signal } from "@/api/types";
import { Empty } from "@/components/ui";

export function Meter({ value, label }: { value: number; label: string }) {
  const v = Math.max(0, Math.min(100, value));
  const level = v >= 70 ? ["High", "var(--critical)"] : v >= 35 ? ["Medium", "var(--serious)"] : ["Low", "var(--good)"];
  return (
    <div>
      <div className="flex items-baseline justify-between text-xs text-ink-2">
        <span>{label}</span>
        <span className="text-base font-semibold tabular-nums text-ink">
          {Math.round(v)}/100 <span className="text-xs font-medium" style={{ color: level[1] }}>{level[0]}</span>
        </span>
      </div>
      <div
        className="mt-1 h-2.5 overflow-hidden rounded-full bg-surface-2"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(v)}
      >
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${v}%`, background: level[1] }} />
      </div>
    </div>
  );
}

export function WeightBar({ weight, max = 1 }: { weight: number; max?: number }) {
  const w = Math.max(0, Math.min(100, (weight / max) * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-2" aria-hidden>
        <div className="h-full rounded-full bg-series-1" style={{ width: `${w}%` }} />
      </div>
      <span className="text-xs tabular-nums text-ink-2">{weight.toFixed(2)}</span>
    </div>
  );
}

export function SignalList({ signals, emptyTitle = "No suspicious signals" }: { signals: Signal[]; emptyTitle?: string }) {
  if (!signals.length) return <Empty title={emptyTitle} hint="Nothing in this input raised a signal." />;
  const max = Math.max(1, ...signals.map((s) => s.weight));
  return (
    <ul className="divide-y divide-line">
      {signals.map((s, i) => (
        <li key={`${s.name}-${i}`} className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1 py-2.5">
          <div className="min-w-0 flex-1 basis-60">
            <div className="font-mono text-[12px] font-medium">{s.name}</div>
            <p className="text-ink-2">{s.detail}</p>
          </div>
          <div className="pt-1">
            <span className="sr-only">Weight</span>
            <WeightBar weight={s.weight} max={max} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export function Chip({ children }: { children: React.ReactNode }) {
  return <span className="inline-flex items-center rounded-md border border-line bg-surface-2 px-2 py-0.5 text-xs text-ink-2">{children}</span>;
}
