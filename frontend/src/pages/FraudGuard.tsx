import { useMutation } from "@tanstack/react-query";
import { Ban, Bot, CheckCircle2, CircleAlert, CircleDollarSign, ClipboardPaste, Cpu, HelpCircle, KeyRound, ShieldAlert, User, XCircle } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/client";
import type { BotScore, FraudAssessment } from "@/api/types";
import { Meter, SignalList } from "@/components/detect/shared";
import { Analyzing, Badge, Button, Card, ErrorNote, ExampleChips, Field, FormSection, HowItWorks, PageHeader, ResultBanner, inputClass } from "@/components/ui";

const PRESETS = [
  { label: "Normal refund ₹499", amount: "499", payee: "customer-4821@okaxis", hour: "14", untrusted: false },
  { label: "Just under limit ₹9,900", amount: "9900", payee: "new-vendor@ybl", hour: "11", untrusted: false },
  { label: "₹2.5 lakh to new payee at 3am", amount: "250000", payee: "unknown-account-998877", hour: "3", untrusted: true },
];

const PAY = {
  allow: { tone: "good", icon: CheckCircle2, title: "Safe to proceed", note: "This payment looks normal.", next: "Let the agent complete the payment." },
  require_approval: { tone: "warn", icon: ShieldAlert, title: "Needs a human to approve", note: "The risk is elevated, so a person should confirm.", next: "Ask the account owner to approve it with step-up authentication before it is sent." },
  block: { tone: "critical", icon: Ban, title: "Blocked: do not send", note: "This payment is too risky to allow.", next: "Stop the payment and review what instructed the agent to make it." },
} as const;

function TransactionCard() {
  const [agent, setAgent] = useState("email-assistant");
  const [amount, setAmount] = useState("");
  const [payee, setPayee] = useState("");
  const [hour, setHour] = useState("");
  const [untrusted, setUntrusted] = useState(false);

  const m = useMutation({
    mutationFn: () =>
      api.post<FraudAssessment>("/fraud/assess", {
        agent_id: agent,
        amount: Number(amount),
        payee,
        hour: hour === "" ? null : Number(hour),
        untrusted_origin: untrusted,
      }),
  });
  const valid = agent.trim() !== "" && amount !== "" && Number(amount) >= 0 && (hour === "" || (Number(hour) >= 0 && Number(hour) <= 23));
  const r = m.data;

  return (
    <Card title="Check a payment">
      <p className="mb-3 text-sm text-ink-2">An AI agent wants to send money. Enter the payment details and we'll tell you whether to allow it, ask a human, or block it.</p>
      <ExampleChips
        items={PRESETS.map((p) => ({
          label: p.label,
          onPick: () => {
            setAmount(p.amount);
            setPayee(p.payee);
            setHour(p.hour);
            setUntrusted(p.untrusted);
            m.reset();
          },
        }))}
      />
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <FormSection n={1} title="The payment">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Amount (₹)" required hint="Total value of the payment">
              <input className={inputClass} type="number" min={0} step="any" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="e.g. 9900" />
            </Field>
            <Field label="Who gets the money (payee)" hint="UPI ID, account number or vendor name">
              <input className={inputClass} value={payee} onChange={(e) => setPayee(e.target.value)} placeholder="e.g. vendor@okaxis" />
            </Field>
          </div>
        </FormSection>
        <FormSection n={2} title="The context" desc="Details that make a payment more or less risky.">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Which agent requested it" required>
              <input className={inputClass} value={agent} onChange={(e) => setAgent(e.target.value)} />
            </Field>
            <Field label="Hour of day it happened" optional hint="24-hour clock, 0 to 23. Night-time is riskier.">
              <input className={inputClass} type="number" min={0} max={23} value={hour} onChange={(e) => setHour(e.target.value)} placeholder="e.g. 3" />
            </Field>
          </div>
          <label className="flex items-start gap-2 rounded-lg border border-line bg-surface p-2.5 text-sm">
            <input type="checkbox" className="mt-0.5 size-4 accent-[var(--accent)]" checked={untrusted} onChange={(e) => setUntrusted(e.target.checked)} />
            <span>
              The payee or amount came from an email, web page or document
              <span className="block text-xs text-ink-3">Tick this if the agent didn't get these details directly from the user. It's a common sign of a hijacked agent.</span>
            </span>
          </label>
        </FormSection>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" className="px-4 py-2" loading={m.isPending} disabled={!valid}>
            <CircleDollarSign size={15} aria-hidden /> Check this payment
          </Button>
          {!valid && <span className="text-xs text-ink-3">Enter an amount to continue.</span>}
        </div>
      </form>
      <p className="mt-3 text-xs text-ink-3">
        Rules of thumb: ₹10,000 or more needs human approval; ₹5,00,000 or more is blocked. New payees, odd hours, amounts just under a limit and untrusted origin all raise the risk.
      </p>
      {m.isError && <div className="mt-3"><ErrorNote error={m.error} /></div>}
      {m.isPending && <div className="mt-4"><Analyzing steps={["Comparing amount against limits", "Checking payee and timing", "Looking for structuring patterns"]} /></div>}
      {r && !m.isPending && (
        <div className="mt-4">
          <ResultBanner tone={PAY[r.verdict].tone} icon={PAY[r.verdict].icon} title={PAY[r.verdict].title} note={PAY[r.verdict].note} next={PAY[r.verdict].next}>
            <div className="space-y-3">
              <Meter value={r.score * 100} label="Fraud risk" />
              <SignalList signals={r.signals} emptyTitle="No risk signals" />
            </div>
          </ResultBanner>
        </div>
      )}
    </Card>
  );
}

function genHuman(n = 24): number[] {
  const out: number[] = [];
  let t = Date.now();
  for (let i = 0; i < n; i++) {
    t += 400 + Math.random() * 4200 * (Math.random() < 0.2 ? 3 : 1);
    out.push(Math.round(t));
  }
  return out;
}
function genBot(n = 24): number[] {
  const t0 = Date.now();
  return Array.from({ length: n }, (_, i) => t0 + i * 500);
}

const BOT_VERDICT = {
  bot: { tone: "critical", icon: Bot, label: "Looks like a bot", note: "Requests arrive with machine-like regularity." },
  human_like: { tone: "good", icon: User, label: "Looks human", note: "The timing is irregular, like a real person." },
  insufficient_data: { tone: "neutral", icon: HelpCircle, label: "Not enough data", note: "Add more timestamps (about 10 or more) for a reliable answer." },
} as const;

function parseTs(text: string): number[] {
  return text
    .split(/[\s,;]+/)
    .filter(Boolean)
    .map(Number);
}

function BotCard() {
  const [text, setText] = useState("");
  const [agent, setAgent] = useState("email-assistant");
  const [sig, setSig] = useState("");

  const ts = parseTs(text);
  const bad = text.trim() !== "" && ts.some((x) => !Number.isFinite(x));

  const bot = useMutation({ mutationFn: () => api.post<BotScore>("/fraud/bot-score", { timestamps_ms: ts }) });
  const cred = useMutation({
    mutationFn: () => api.get<{ signature: string }>(`/agents/${encodeURIComponent(agent)}/credential`),
    onSuccess: (d) => {
      setSig(d.signature);
      verify.reset();
    },
  });
  const verify = useMutation({
    mutationFn: () => api.post<{ verified: boolean }>("/fraud/verify-identity", { agent_id: agent, signature: sig || null }),
  });

  const b = bot.data;
  const bv = b ? BOT_VERDICT[b.verdict] : null;

  return (
    <Card title="Bot and identity checks">
      <p className="mb-3 text-sm text-ink-2">Two quick checks: does the request rhythm look automated, and does the agent's signed ID hold up?</p>
      <h3 className="mb-2 flex items-center gap-1.5 text-sm font-semibold"><Cpu size={15} aria-hidden /> A. Request timing</h3>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          bot.mutate();
        }}
      >
        <Field label="When did the requests arrive?" required hint="Paste Unix timestamps in milliseconds, one per line or separated by commas. Bots tend to be evenly spaced; people are irregular. No data? Use a sample button below.">
          <textarea className={`${inputClass} min-h-28 font-mono text-[12px]`} value={text} onChange={(e) => setText(e.target.value)} aria-invalid={bad} placeholder={"1718000000000\n1718000000500\n1718000001000"} />
        </Field>
        {ts.length > 0 && !bad && <p className="text-xs text-ink-3">{ts.length} timestamp{ts.length === 1 ? "" : "s"} detected</p>}
        {bad && <p className="text-xs text-critical" role="alert">Timestamps must be numbers.</p>}
        <div className="flex flex-wrap gap-2">
          <Button type="button" onClick={() => { setText(genHuman().join("\n")); bot.reset(); }}>
            <User size={14} aria-hidden /> Fill with human-like sample
          </Button>
          <Button type="button" onClick={() => { setText(genBot().join("\n")); bot.reset(); }}>
            <Bot size={14} aria-hidden /> Fill with bot-like sample
          </Button>
          <Button type="submit" variant="primary" loading={bot.isPending} disabled={ts.length === 0 || bad}>
            Check timing
          </Button>
        </div>
      </form>
      {bot.isError && <div className="mt-3"><ErrorNote error={bot.error} /></div>}
      {b && bv && (
        <div className="mt-4">
          <ResultBanner tone={bv.tone} icon={bv.icon} title={bv.label} note={bv.note}>
            <div className="space-y-3">
              <Meter value={b.score * 100} label="Bot likelihood" />
              <SignalList signals={b.signals} emptyTitle="No bot signals" />
            </div>
          </ResultBanner>
        </div>
      )}

      <div className="mt-6 border-t border-line pt-4">
        <h3 className="mb-2 flex items-center gap-1.5 text-sm font-semibold">
          <KeyRound size={15} aria-hidden /> B. Agent identity check
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Agent ID">
            <input className={inputClass} value={agent} onChange={(e) => { setAgent(e.target.value); verify.reset(); }} />
          </Field>
          <Field label="Signature" hint="The agent's signed credential. Click 'Issue sample credential' to get a valid one.">
            <input className={`${inputClass} font-mono text-[12px]`} value={sig} onChange={(e) => { setSig(e.target.value); verify.reset(); }} />
          </Field>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => cred.mutate()} loading={cred.isPending} disabled={!agent.trim()}>
            Issue sample credential
          </Button>
          <Button type="button" variant="primary" onClick={() => verify.mutate()} loading={verify.isPending} disabled={!agent.trim()}>
            Verify identity
          </Button>
          {verify.data &&
            (verify.data.verified ? (
              <Badge tone="good" icon={CheckCircle2}>Identity verified</Badge>
            ) : (
              <Badge tone="critical" icon={XCircle}>Not verified: signature forged or missing</Badge>
            ))}
        </div>
        {(cred.isError || verify.isError) && (
          <div className="mt-3"><ErrorNote error={cred.error ?? verify.error} /></div>
        )}
        <p className="mt-2 flex items-start gap-1 text-xs text-ink-3">
          <CircleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />
          Edit the signature to see verification fail: a forged or missing signature is reported as unverified.
        </p>
      </div>
    </Card>
  );
}

export default function FraudGuard() {
  return (
    <>
      <PageHeader
        icon={CircleDollarSign}
        title="Fraud Guard"
        subtitle="Before an AI agent moves money, check the payment, check whether the traffic is a bot, and confirm the agent is who it claims to be."
      />
      <HowItWorks
        steps={[
          { icon: ClipboardPaste, title: "Enter the details", text: "A payment's amount and payee, a list of request times, or an agent ID." },
          { icon: Cpu, title: "We score the risk", text: "Limits, timing, new payees and signature checks are weighed together." },
          { icon: ShieldAlert, title: "Allow, approve or block", text: "You get a clear decision, the reasons, and the next step." },
        ]}
      />
      <div className="grid items-start gap-4 xl:grid-cols-2">
        <TransactionCard />
        <BotCard />
      </div>
    </>
  );
}
