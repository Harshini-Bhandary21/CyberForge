import { titleCase } from "@/lib/format";

const LABEL_COLOR: Record<string, string> = {
  low: "var(--good)",
  moderate: "var(--warn)",
  high: "var(--serious)",
  critical: "var(--critical)",
};

/** Semicircle gauge: 0 (best) → 100 (worst). The label + number carry the meaning; colour is secondary. */
export function RiskGauge({ score, label }: { score: number; label: string }) {
  const R = 78;
  const C = Math.PI * R;
  const dash = (Math.min(Math.max(score, 0), 100) / 100) * C;
  return (
    <figure className="m-0 flex flex-col items-center" aria-label={`AI risk score ${score} out of 100, ${label}`}>
      <svg viewBox="0 0 200 118" className="w-full max-w-[260px]">
        <path d="M 22 100 A 78 78 0 0 1 178 100" fill="none" stroke="var(--line)" strokeWidth={12} strokeLinecap="round" />
        <path
          d="M 22 100 A 78 78 0 0 1 178 100"
          fill="none"
          stroke={LABEL_COLOR[label] ?? "var(--accent)"}
          strokeWidth={12}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${C}`}
        />
        <text x={100} y={90} textAnchor="middle" fontSize={38} fontWeight={600} fill="var(--ink)" className="tabular-nums">
          {score}
        </text>
        <text x={100} y={110} textAnchor="middle" fontSize={12} fill="var(--ink-2)">
          {titleCase(label)} risk
        </text>
      </svg>
    </figure>
  );
}
