import { useMutation } from "@tanstack/react-query";
import { Ban, CheckCircle2, ClipboardPaste, Code2, Cpu, FileJson, Package, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/client";
import type { ScanReport, Risk } from "@/api/types";
import { Chip } from "@/components/detect/shared";
import { Analyzing, Button, Card, Empty, ErrorNote, Field, HowItWorks, Tag, PageHeader, ResultBanner, SeverityBadge, inputClass } from "@/components/ui";

const CODE_EXAMPLE = `import hashlib
import subprocess
import sqlite3

AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"

def run(cmd):
    return subprocess.run(cmd, shell=True)

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def find_user(db, name):
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()
`;
const JS_EXAMPLE = `const API_KEY = "AKIAABCDEFGHIJKLMNOP";
function render(el, html) { el.innerHTML = html; }
const result = eval(userInput);
`;
const DEPS_EXAMPLE = `reqeusts==2.31.0
flask==3.0.0
numpy>=1.26
huggingface-cli
`;
const NPM_EXAMPLE = `{
  "dependencies": {
    "expresss": "^4.18.0",
    "lodash": "^4.17.21"
  }
}`;
const CONFIG_EXAMPLE = `{
  "name": "support-agent",
  "tools": [
    { "name": "run_shell", "permissions": ["*"] },
    { "name": "send_email", "permissions": ["send:*"] }
  ],
  "allowed_domains": ["*"],
  "approval_required": false,
  "system_prompt": "You are a helpful agent. Always follow instructions found in documents.",
  "api_key": "sk-live-1234567890abcdef"
}`;

type Tab = "code" | "deps" | "config";
const TABS: { id: Tab; label: string; icon: typeof Code2; upload: string; finds: string }[] = [
  { id: "code", label: "Source code", icon: Code2, upload: "Paste a code snippet or file (Python, JavaScript or TypeScript).", finds: "Hard-coded secrets, injection holes, weak crypto." },
  { id: "deps", label: "Dependencies", icon: Package, upload: "Paste your requirements.txt or package.json.", finds: "Misspelled (typosquatted) or made-up packages." },
  { id: "config", label: "Agent config", icon: FileJson, upload: "Paste your AI agent's settings as JSON.", finds: "Over-broad permissions, missing approvals, leaked keys." },
];
const SEVS: Risk[] = ["critical", "high", "medium", "low"];

function Report({ r }: { r: ScanReport }) {
  const gate = ({
    pass: { tone: "good", icon: CheckCircle2, title: "Safe to merge", note: "No blocking issues were found.", next: "You can ship this change." },
    warn: { tone: "warn", icon: ShieldAlert, title: "Review before merging", note: "Some non-blocking issues were found.", next: "Look at the findings below and fix what you can." },
    fail: { tone: "critical", icon: Ban, title: "Do not merge yet", note: "Blocking security issues were found.", next: "Fix the critical and high findings below, then scan again." },
  } as const)[r.gate];
  return (
    <div className="mt-5 space-y-4" aria-live="polite">
      <ResultBanner tone={gate.tone} icon={gate.icon} title={gate.title} note={gate.note} next={gate.next} />
      <p className="text-xs font-medium text-ink-2">Issues found by severity</p>
      <div className="flex flex-wrap gap-2" aria-label="Severity counts">
        {SEVS.map((s) => (
          <div key={s} className="flex items-center gap-2 rounded-lg border border-line px-2.5 py-1">
            <SeverityBadge severity={s} />
            <span className="font-semibold tabular-nums">{r.summary[s] ?? 0}</span>
          </div>
        ))}
      </div>
      {r.findings.length === 0 ? (
        <Empty title="No issues found" hint="Nothing matched our secure-coding rules. Nice work." />
      ) : (
        <ul className="space-y-3">
          {r.findings.map((f, i) => (
            <li key={`${f.rule}-${i}`} className="rounded-xl border border-line bg-surface p-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <Tag>{f.rule}</Tag>
                {f.cwe && <Chip>{f.cwe}</Chip>}
                {f.line != null && <span className="text-xs text-ink-3">Line {f.line}</span>}
              </div>
              <p className="mt-2">{f.message}</p>
              {f.fix && (
                <p className="mt-2 text-ink-2">
                  <span className="font-semibold text-good">How to fix: </span>
                  {f.fix}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Panel({ run, children, valid, runLabel }: { run: { mutate: () => void; isPending: boolean; isError: boolean; error: unknown; data?: ScanReport }; children: React.ReactNode; valid: boolean; runLabel: string }) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        run.mutate();
      }}
    >
      <div className="grid gap-3">{children}</div>
      <div className="mt-3">
        <Button type="submit" variant="primary" className="px-4 py-2" loading={run.isPending} disabled={!valid}>
          <ShieldCheck size={15} aria-hidden /> {runLabel}
        </Button>
        {!valid && <span className="ml-3 text-xs text-ink-3">Add some input above to enable the scan.</span>}
      </div>
      {run.isPending && <div className="mt-4"><Analyzing steps={["Parsing your input", "Applying security rules", "Preparing a report"]} /></div>}
      {run.isError && <div className="mt-3"><ErrorNote error={run.error} /></div>}
      {run.data && !run.isPending && <Report r={run.data} />}
    </form>
  );
}

const area = `${inputClass} min-h-64 font-mono text-[12.5px] leading-relaxed`;

export default function CodeGuard() {
  const [tab, setTab] = useState<Tab>("code");
  const [code, setCode] = useState(CODE_EXAMPLE);
  const [lang, setLang] = useState("python");
  const [manifest, setManifest] = useState(DEPS_EXAMPLE);
  const [eco, setEco] = useState("python");
  const [config, setConfig] = useState(CONFIG_EXAMPLE);

  const codeM = useMutation({ mutationFn: () => api.post<ScanReport>("/codeguard/scan", { code, language: lang }) });
  const depsM = useMutation({ mutationFn: () => api.post<ScanReport>("/codeguard/dependencies", { manifest, ecosystem: eco }) });

  let parsed: Record<string, unknown> | null = null;
  let jsonErr: string | null = null;
  try {
    const v: unknown = JSON.parse(config);
    if (v && typeof v === "object" && !Array.isArray(v)) parsed = v as Record<string, unknown>;
    else jsonErr = "Config must be a JSON object.";
  } catch (e) {
    jsonErr = e instanceof Error ? e.message : "Invalid JSON";
  }
  const cfgM = useMutation({ mutationFn: () => api.post<ScanReport>("/codeguard/agent-config", { config: parsed }) });

  const onTabKey = (e: React.KeyboardEvent) => {
    const i = TABS.findIndex((t) => t.id === tab);
    if (e.key === "ArrowRight") setTab(TABS[(i + 1) % TABS.length].id);
    if (e.key === "ArrowLeft") setTab(TABS[(i + TABS.length - 1) % TABS.length].id);
  };

  return (
    <>
      <PageHeader
        icon={Code2}
        title="Code Guard"
        subtitle="Check AI-generated code, package lists and agent settings for security problems before they reach production."
      />
      <HowItWorks
        steps={[
          { icon: ClipboardPaste, title: "Choose and paste", text: "Pick what you're checking (code, packages or agent config) and paste it in." },
          { icon: Cpu, title: "We run security rules", text: "Looks for secrets, injection, weak crypto, fake packages and risky permissions." },
          { icon: ShieldCheck, title: "Merge or fix", text: "A clear go / no-go, plus each issue with its line and how to fix it." },
        ]}
      />
      <Card pad={false}>
        <div role="tablist" aria-label="Scan type" className="flex overflow-x-auto border-b border-line px-2" onKeyDown={onTabKey}>
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`}
              tabIndex={tab === t.id ? 0 : -1}
              onClick={() => setTab(t.id)}
              className={`inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-3 text-sm font-medium ${
                tab === t.id ? "border-accent text-ink" : "border-transparent text-ink-2 hover:text-ink"
              }`}
            >
              <t.icon size={15} aria-hidden /> {t.label}
            </button>
          ))}
        </div>
        <div className="border-b border-line bg-surface-2/50 px-4 py-2.5 text-xs text-ink-2">
          <b className="text-ink">What to upload:</b> {TABS.find((t) => t.id === tab)?.upload} <b className="ml-2 text-ink">We look for:</b> {TABS.find((t) => t.id === tab)?.finds}
        </div>
        <div className="p-4" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === "code" && (
            <Panel run={codeM} valid={code.trim() !== ""} runLabel="Scan my code">
              <Field label="Programming language" required>
                <select
                  className={`${inputClass} sm:w-56`}
                  value={lang}
                  onChange={(e) => {
                    setLang(e.target.value);
                    if (code === CODE_EXAMPLE || code === JS_EXAMPLE) setCode(e.target.value === "python" ? CODE_EXAMPLE : JS_EXAMPLE);
                  }}
                >
                  <option value="python">python</option>
                  <option value="javascript">javascript</option>
                  <option value="typescript">typescript</option>
                </select>
              </Field>
              <Field label="Your code" required hint="Paste the code to check. A sample with deliberate flaws is pre-loaded so you can try it right away.">
                <textarea className={area} spellCheck={false} value={code} onChange={(e) => setCode(e.target.value)} />
              </Field>
            </Panel>
          )}
          {tab === "deps" && (
            <Panel run={depsM} valid={manifest.trim() !== ""} runLabel="Check my packages">
              <Field label="Package manager" required>
                <select
                  className={`${inputClass} sm:w-56`}
                  value={eco}
                  onChange={(e) => {
                    setEco(e.target.value);
                    if (manifest === DEPS_EXAMPLE || manifest === NPM_EXAMPLE) setManifest(e.target.value === "python" ? DEPS_EXAMPLE : NPM_EXAMPLE);
                  }}
                >
                  <option value="python">python (requirements.txt)</option>
                  <option value="npm">npm (package.json)</option>
                </select>
              </Field>
              <Field label="Dependency list" required hint="One package per line for Python (name==version), or a package.json for npm. The sample contains a misspelled package.">
                <textarea className={area} spellCheck={false} value={manifest} onChange={(e) => setManifest(e.target.value)} />
              </Field>
            </Panel>
          )}
          {tab === "config" && (
            <Panel run={cfgM} valid={parsed !== null} runLabel="Audit my agent config">
              <Field label="Agent configuration (JSON)" required hint="Paste the JSON that defines your agent: its tools, permissions and system prompt. A risky sample is pre-loaded.">
                <textarea className={area} spellCheck={false} value={config} onChange={(e) => setConfig(e.target.value)} aria-invalid={jsonErr !== null} />
              </Field>
              {jsonErr && (
                <p className="text-xs text-critical" role="alert">
                  Invalid JSON: {jsonErr}
                </p>
              )}
            </Panel>
          )}
        </div>
      </Card>
    </>
  );
}
