import { useState } from "react";
import { pct } from "@/lib/format";

export interface BarRow {
  label: string;
  a: number; // 0..1 (series 1)
  b?: number; // 0..1 (series 2, optional)
  n?: number;
}

/**
 * Horizontal paired bars on one 0–100% axis. Series colours come from the categorical order
 * (slot 1 blue, slot 2 orange); identity is carried by the legend + direct value labels, not colour alone.
 */
export function BarCompare({
  rows,
  aLabel,
  bLabel,
  labelWidth = 150,
}: {
  rows: BarRow[];
  aLabel: string;
  bLabel?: string;
  labelWidth?: number;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const rowH = bLabel ? 34 : 22;
  const barH = bLabel ? 9 : 12;
  const W = 560;
  const plotX = labelWidth;
  const plotW = W - plotX - 52;
  const H = rows.length * rowH + 22;

  return (
    <figure className="m-0">
      <div className="mb-2 flex flex-wrap gap-4 text-xs text-ink-2" aria-hidden>
        <span className="inline-flex items-center gap-1.5">
          <i className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--series-1)" }} />
          {aLabel}
        </span>
        {bLabel && (
          <span className="inline-flex items-center gap-1.5">
            <i className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--series-2)" }} />
            {bLabel}
          </span>
        )}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`${aLabel}${bLabel ? ` versus ${bLabel}` : ""} by category`}>
        {[0, 0.5, 1].map((t) => (
          <g key={t}>
            <line x1={plotX + t * plotW} x2={plotX + t * plotW} y1={0} y2={H - 18} stroke="var(--line)" strokeWidth={1} />
            <text x={plotX + t * plotW} y={H - 4} textAnchor="middle" fontSize={10} fill="var(--ink-3)">
              {t * 100}%
            </text>
          </g>
        ))}
        {rows.map((r, i) => {
          const y = i * rowH + 4;
          const wa = Math.max(r.a * plotW, r.a > 0 ? 2 : 0);
          const wb = Math.max((r.b ?? 0) * plotW, (r.b ?? 0) > 0 ? 2 : 0);
          return (
            <g key={r.label} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(i)} onBlur={() => setHover(null)} tabIndex={0}>
              <rect x={0} y={y - 2} width={W} height={rowH} fill={hover === i ? "var(--surface-2)" : "transparent"} rx={4} />
              <text x={0} y={y + (bLabel ? 14 : 12)} fontSize={12} fill="var(--ink-2)">
                {r.label}
              </text>
              <rect x={plotX} y={y + 2} width={wa} height={barH} rx={2} fill="var(--series-1)" />
              <text x={plotX + wa + 6} y={y + 2 + barH - 1} fontSize={11} fill="var(--ink)" className="tabular-nums">
                {pct(r.a)}
              </text>
              {bLabel && (
                <>
                  <rect x={plotX} y={y + 2 + barH + 3} width={wb} height={barH} rx={2} fill="var(--series-2)" />
                  <text x={plotX + wb + 6} y={y + 2 + 2 * barH + 2} fontSize={11} fill="var(--ink)" className="tabular-nums">
                    {pct(r.b ?? 0)}
                  </text>
                </>
              )}
              <title>{`${r.label}: ${aLabel} ${pct(r.a)}${bLabel ? `, ${bLabel} ${pct(r.b ?? 0)}` : ""}${r.n ? ` (n=${r.n})` : ""}`}</title>
            </g>
          );
        })}
      </svg>
    </figure>
  );
}
