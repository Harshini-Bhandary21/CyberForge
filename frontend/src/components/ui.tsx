import {
  AlertTriangle,
  ArrowRight,
  Ban,
  CheckCircle2,
  CircleAlert,
  Info,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Risk, Trust, Verdict } from "@/api/types";

/* ───────── Layout primitives ───────── */

export function PageHeader({
  title,
  subtitle,
  actions,
  icon: Icon,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div className="flex items-start gap-3">
        {Icon && (
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-[var(--accent)] to-[var(--grad-end)] text-white shadow-sm">
            <Icon size={22} aria-hidden />
          </span>
        )}
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="mt-1 max-w-3xl text-ink-2">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Three-step strip that tells the user what to provide, what happens, and what they get back. */
export function HowItWorks({ steps }: { steps: { icon: LucideIcon; title: string; text: string }[] }) {
  return (
    <ol className="mb-6 grid gap-3 sm:grid-cols-3" aria-label="How this works">
      {steps.map((st, i) => (
        <li key={st.title} className="relative flex gap-3 rounded-xl border border-line bg-surface p-3.5 shadow-sm">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--info-bg)] text-accent">
            <st.icon size={18} aria-hidden />
          </span>
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">Step {i + 1}</div>
            <div className="font-medium leading-tight">{st.title}</div>
            <p className="mt-0.5 text-xs text-ink-2">{st.text}</p>
          </div>
          {i < steps.length - 1 && (
            <ArrowRight size={16} className="absolute -right-2.5 top-1/2 z-[1] hidden -translate-y-1/2 rounded-full bg-bg text-ink-3 sm:block" aria-hidden />
          )}
        </li>
      ))}
    </ol>
  );
}

/** Numbered form section: says what this part of the form is for. */
export function FormSection({ n, title, desc, children }: { n?: number; title: string; desc?: ReactNode; children: ReactNode }) {
  return (
    <fieldset className="rounded-xl border border-line bg-surface-2/50 p-3.5">
      <legend className="sr-only">{title}</legend>
      <div className="mb-3 flex items-start gap-2.5">
        {n != null && <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-accent text-xs font-semibold text-white">{n}</span>}
        <div>
          <div className="text-sm font-semibold leading-6">{title}</div>
          {desc && <p className="text-xs text-ink-2">{desc}</p>}
        </div>
      </div>
      <div className="space-y-3">{children}</div>
    </fieldset>
  );
}

/** Large, colour-coded outcome header with an icon, a plain-language headline and a "what to do next" line. */
export function ResultBanner({
  tone,
  icon: Icon,
  title,
  note,
  next,
  children,
}: {
  tone: Tone;
  icon: LucideIcon;
  title: ReactNode;
  note?: ReactNode;
  next?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className={`result-pop overflow-hidden rounded-xl border border-line bg-surface shadow-sm`} aria-live="polite">
      <div className={`flex items-center gap-4 border-l-4 p-4 ${BANNER[tone]}`}>
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-full bg-surface/70">
          <Icon size={28} className={ICON_COLOR[tone]} aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-xl font-semibold leading-tight">{title}</div>
          {note && <div className="mt-0.5 text-ink-2">{note}</div>}
        </div>
      </div>
      {next && (
        <div className="flex items-start gap-2 border-t border-line bg-surface-2/60 px-4 py-2.5 text-sm">
          <ArrowRight size={15} className="mt-1 shrink-0 text-accent" aria-hidden />
          <span>
            <b>What to do next: </b>
            {next}
          </span>
        </div>
      )}
      {children && <div className="border-t border-line p-4">{children}</div>}
    </div>
  );
}

/** Friendly placeholder shown in the results column before anything has been run. */
export function ResultPlaceholder({ icon: Icon, title, lines }: { icon: LucideIcon; title: string; lines: string[] }) {
  return (
    <div className="rounded-xl border border-dashed border-line bg-surface/60 px-5 py-8 text-center">
      <span className="mx-auto mb-3 grid h-12 w-12 place-items-center rounded-full bg-surface-2 text-ink-3">
        <Icon size={24} aria-hidden />
      </span>
      <p className="font-medium">{title}</p>
      <ul className="mx-auto mt-2 max-w-sm space-y-1 text-left text-xs text-ink-2">
        {lines.map((l) => (
          <li key={l} className="flex gap-1.5">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-ink-3" aria-hidden /> {l}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Animated "working" panel so people can see the scan is actually running. */
export function Analyzing({ steps }: { steps: string[] }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-5" role="status">
      <div className="mb-3 flex items-center gap-2 font-medium">
        <Loader2 size={16} className="animate-spin text-accent" aria-hidden /> Analysing…
      </div>
      <ul className="space-y-1.5 text-sm text-ink-2">
        {steps.map((t, i) => (
          <li key={t} className="step-in flex items-center gap-2" style={{ animationDelay: `${i * 350}ms` }}>
            <span className="h-1.5 w-1.5 rounded-full bg-accent" aria-hidden /> {t}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Card({
  title,
  action,
  children,
  className = "",
  pad = true,
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  pad?: boolean;
}) {
  return (
    <section className={`rounded-xl border border-line bg-surface shadow-sm ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  icon: Icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4">
      <div className="flex items-center justify-between text-ink-3">
        <span className="text-xs font-medium">{label}</span>
        {Icon && <Icon size={15} aria-hidden />}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-ink-3">{hint}</div>}
    </div>
  );
}

/* ───────── Badges (status always pairs colour with icon + label) ───────── */

export type Tone = "neutral" | "good" | "warn" | "serious" | "critical" | "info";
const TONES: Record<Tone, string> = {
  neutral: "bg-surface-2 text-ink-2",
  good: "bg-[var(--good-bg)] text-ink",
  warn: "bg-[var(--warn-bg)] text-ink",
  serious: "bg-[var(--serious-bg)] text-ink",
  critical: "bg-[var(--critical-bg)] text-ink",
  info: "bg-[var(--info-bg)] text-ink",
};
const ICON_COLOR: Record<Tone, string> = {
  neutral: "text-ink-3",
  good: "text-good",
  warn: "text-warn",
  serious: "text-serious",
  critical: "text-critical",
  info: "text-accent",
};

const BANNER: Record<Tone, string> = {
  neutral: "border-l-[var(--ink-3)] bg-surface-2",
  good: "border-l-[var(--good)] bg-[var(--good-bg)]",
  warn: "border-l-[var(--warn)] bg-[var(--warn-bg)]",
  serious: "border-l-[var(--serious)] bg-[var(--serious-bg)]",
  critical: "border-l-[var(--critical)] bg-[var(--critical-bg)]",
  info: "border-l-[var(--accent)] bg-[var(--info-bg)]",
};

export function Badge({ tone = "neutral", icon: Icon, children }: { tone?: Tone; icon?: LucideIcon; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${TONES[tone]}`}>
      {Icon && <Icon size={12} className={ICON_COLOR[tone]} aria-hidden />}
      {children}
    </span>
  );
}

const VERDICTS: Record<Verdict, { tone: Tone; icon: LucideIcon; label: string }> = {
  allow: { tone: "good", icon: CheckCircle2, label: "Allowed" },
  require_approval: { tone: "warn", icon: ShieldAlert, label: "Needs approval" },
  block: { tone: "critical", icon: Ban, label: "Blocked" },
};
export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const v = VERDICTS[verdict];
  return (
    <Badge tone={v.tone} icon={v.icon}>
      {v.label}
    </Badge>
  );
}

const SEVERITY: Record<Risk, { tone: Tone; icon: LucideIcon }> = {
  low: { tone: "info", icon: Info },
  medium: { tone: "warn", icon: AlertTriangle },
  high: { tone: "serious", icon: AlertTriangle },
  critical: { tone: "critical", icon: CircleAlert },
};
export function SeverityBadge({ severity }: { severity: Risk }) {
  const s = SEVERITY[severity];
  return (
    <Badge tone={s.tone} icon={s.icon}>
      {severity[0].toUpperCase() + severity.slice(1)}
    </Badge>
  );
}

export function TrustBadge({ trust }: { trust: Trust }) {
  if (trust === "trusted")
    return (
      <Badge tone="good" icon={ShieldCheck}>
        Trusted
      </Badge>
    );
  if (trust === "hostile")
    return (
      <Badge tone="critical" icon={Ban}>
        Hostile
      </Badge>
    );
  return (
    <Badge tone="neutral" icon={Info}>
      Untrusted
    </Badge>
  );
}

export function StatusPill({ status }: { status: "satisfied" | "partial" | "gap" | "pass" | "warn" | "fail" }) {
  const map = {
    satisfied: ["good", CheckCircle2, "Satisfied"],
    pass: ["good", CheckCircle2, "Pass"],
    partial: ["warn", AlertTriangle, "Partial"],
    warn: ["warn", AlertTriangle, "Warn"],
    gap: ["critical", CircleAlert, "Gap"],
    fail: ["critical", CircleAlert, "Fail"],
  } as const;
  const [tone, icon, label] = map[status];
  return (
    <Badge tone={tone} icon={icon}>
      {label}
    </Badge>
  );
}

/* ───────── Controls ───────── */

export function Button({
  variant = "secondary",
  loading,
  className = "",
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost"; loading?: boolean }) {
  const styles = {
    primary: "bg-gradient-to-br from-[var(--accent)] to-[var(--grad-end)] text-white shadow-sm hover:brightness-110",
    secondary: "border border-line bg-surface hover:bg-surface-2",
    danger: "bg-critical text-white hover:brightness-110",
    ghost: "hover:bg-surface-2",
  }[variant];
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`}
    >
      {loading && <Loader2 size={14} className="animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

const field =
  "w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm placeholder:text-ink-3 focus:border-accent focus:outline-none";
export const inputClass = field;

export function Field({
  label,
  children,
  hint,
  required,
  optional,
}: {
  label: string;
  children: ReactNode;
  hint?: ReactNode;
  required?: boolean;
  optional?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center gap-1.5 text-[13px] font-medium text-ink">
        {label}
        {required && <span className="text-critical" title="Required" aria-label="required">*</span>}
        {optional && <span className="rounded bg-surface-2 px-1.5 text-[10px] font-medium uppercase tracking-wide text-ink-3">Optional</span>}
      </span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-3">{hint}</span>}
    </label>
  );
}

/** Click-to-fill sample chips; makes it obvious what a valid input looks like. */
export function ExampleChips({ label = "Try a sample", items }: { label?: string; items: { label: string; onPick: () => void; tone?: Tone }[] }) {
  return (
    <div className="mb-4 rounded-xl border border-dashed border-line bg-surface-2/40 p-3">
      <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-ink-2">
        <Sparkles size={13} className="text-accent" aria-hidden /> {label} <span className="font-normal text-ink-3">(click to fill the form)</span>
      </p>
      <div className="flex flex-wrap gap-2">
        {items.map((it) => (
          <button
            key={it.label}
            type="button"
            onClick={it.onPick}
            className="rounded-full border border-line bg-surface px-3 py-1 text-left text-xs font-medium transition hover:border-accent hover:text-accent"
          >
            {it.label}
          </button>
        ))}
      </div>
    </div>
  );
}

/* ───────── Feedback ───────── */

export function Empty({ title, hint, action }: { title: string; hint?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1 px-6 py-10 text-center">
      <ShieldCheck size={28} className="text-ink-3" aria-hidden />
      <p className="font-medium">{title}</p>
      {hint && <p className="max-w-md text-ink-2">{hint}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-ink-3" role="status">
      <Loader2 size={16} className="animate-spin" aria-hidden /> {label}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg bg-[var(--critical-bg)] p-3 text-sm">
      <CircleAlert size={16} className="mt-0.5 shrink-0 text-critical" aria-hidden />
      <span>{error instanceof Error ? error.message : String(error)}</span>
    </div>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[12px]">{children}</code>;
}

export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="max-h-64 overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-[12px] leading-relaxed">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
