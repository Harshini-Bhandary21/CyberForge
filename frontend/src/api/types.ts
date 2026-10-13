/** Mirrors the AgentShield backend (backend/src/agentshield). Keep in sync with /openapi.json. */

export type Risk = "low" | "medium" | "high" | "critical";
export type Verdict = "allow" | "require_approval" | "block";
export type Trust = "trusted" | "untrusted" | "hostile";
export type ContextKind = "user" | "email" | "web" | "document" | "tool_output";

export interface Signal {
  name: string;
  weight: number;
  detail: string;
}

export interface ContextItem {
  id: string;
  kind: ContextKind;
  source: string;
  trust: Trust;
  content: string;
  metadata: Record<string, unknown>;
  risk_score: number;
  signals: Signal[];
  created_at: number;
}

export interface Session {
  id: string;
  agent_id: string;
  user_goal: string;
  capabilities: string[];
  identity_verified: boolean;
  status: "active" | "closed";
  context: ContextItem[];
  call_count: number;
  blocked_count: number;
  created_at: number;
}

export interface Finding {
  rule: string;
  severity: Risk;
  message: string;
  verdict: Verdict;
  evidence: string[];
}

export interface TaintSource {
  item_id: string;
  source: string;
  trust: Trust;
  matched: string[];
  via: "control_arg" | "data_arg" | "declared";
}

export interface VerifierResult {
  aligned: "yes" | "no" | "uncertain";
  confidence: number;
  reasoning: string;
  engine: "heuristic" | "llm";
  provider?: string | null;
}

export interface AnomalyRecord {
  kind: string;
  score: number;
  detail: string;
}

export interface GuardDecision {
  id: string;
  session_id: string;
  agent_id: string;
  tool: string;
  args: Record<string, unknown>;
  verdict: Verdict;
  risk: Risk;
  findings: Finding[];
  taint: { tainted: boolean; sources: TaintSource[] };
  verifier: VerifierResult | null;
  anomalies: AnomalyRecord[];
  approval_id: string | null;
  incident_id: string | null;
  latency_ms: number;
  created_at: number;
}

export interface ToolSpec {
  name: string;
  category: string;
  risk: Risk;
  control_args: string[];
  description: string;
}

export interface Approval {
  id: string;
  session_id: string;
  agent_id: string;
  tool: string;
  args: Record<string, unknown>;
  args_hash: string;
  risk: Risk;
  reasons: string[];
  status: "pending" | "approved" | "denied";
  reviewer: string | null;
  note: string | null;
  created_at: number;
  resolved_at: number | null;
}

export interface TimelineEntry {
  ts: number;
  kind: "context" | "decision" | "anomaly" | "action";
  title: string;
  detail: string;
  severity: Risk;
  ref: string | null;
}

export interface PlannedAction {
  id: string;
  action: "quarantine_agent" | "revoke_tool" | "block_source" | "rotate_credentials" | "notify_owner";
  target: string;
  rationale: string;
  reversible: boolean;
  mode: "executed" | "simulated";
  status: "proposed" | "applied";
  applied_at: number | null;
}

export interface Incident {
  id: string;
  session_id: string;
  agent_id: string;
  goal: string;
  title: string;
  severity: Risk;
  score: number;
  status: "open" | "contained" | "resolved";
  narrative: string;
  timeline: TimelineEntry[];
  actions: PlannedAction[];
  blocked: number;
  approvals: number;
  hostile_sources: string[];
  blocked_tools: string[];
  secrets_seen: boolean;
  max_anomaly: number;
  created_at: number;
  updated_at: number;
}

export interface EmailInput {
  sender: string;
  reply_to: string;
  subject: string;
  body: string;
  headers: Record<string, string>;
}

export interface ScanResult {
  score: number;
  verdict: "benign" | "suspicious" | "malicious";
  signals: Signal[];
  recommended_action: string;
  injection_score: number;
  tactics: string[];
}

export interface CodeFinding {
  rule: string;
  severity: Risk;
  message: string;
  line: number | null;
  cwe: string | null;
  fix: string;
  snippet: string;
}

export interface ScanReport {
  language: string;
  findings: CodeFinding[];
  gate: "pass" | "warn" | "fail";
  summary: Record<string, number>;
}

export interface FraudAssessment {
  score: number;
  verdict: Verdict;
  signals: Signal[];
}

export interface BotScore {
  score: number;
  verdict: "bot" | "human_like" | "insufficient_data";
  signals: Signal[];
}

export interface AgentInfo {
  id: string;
  status: "active" | "quarantined";
  revoked_tools: string[];
  blocked_sources: string[];
  first_seen: number;
  last_seen: number;
  sessions: number;
  baseline: {
    sessions: number;
    calls_mean: number;
    calls_std: number;
    mature: boolean;
    tools: Record<string, number>;
    destinations: string[];
  };
}

export interface AnomalyEvent extends AnomalyRecord {
  id: number;
  ts: number;
  agent_id: string | null;
  session_id: string | null;
}

export interface ControlResult {
  id: string;
  framework: string;
  title: string;
  requirement: string;
  status: "satisfied" | "partial" | "gap";
  evidence: string;
  citations: string[];
  recommendation: string;
}

export interface ComplianceReport {
  generated_at: number;
  coverage_pct: number;
  totals: { satisfied: number; partial: number; gap: number };
  chain: { valid: boolean; length: number; head?: string | null; broken_at: number | null };
  controls: ControlResult[];
  disclaimer: string;
}

export interface RedTeamRun {
  id: string;
  created_at: number;
  params: { cases: number; seed: number; engine: string; payloads: number; mutators: string[] };
  summary: {
    asr_baseline: number;
    asr_protected: number;
    false_block_rate: number;
    friction_rate: number;
    resistance_score: number;
    avg_latency_ms: number;
    p95_latency_ms: number;
  };
  by_category: { category: string; n: number; baseline: number; protected: number }[];
  by_mutator: { mutator: string; n: number; baseline: number; protected: number }[];
  ablations: { config: string; asr: number; false_block_rate: number; friction_rate: number }[];
  defended_by_rule: Record<string, number>;
  breaches: { payload: string; mutator: string; host: string }[];
}

export interface DojoChallenge {
  level: number;
  title: string;
  defence: string;
  objective: string;
  hint: string;
  points: number;
  task_goal: string;
}

export interface DojoAttempt {
  level: number;
  won: boolean;
  points: number;
  agent_hijacked: boolean;
  proposed: { tool: string; args: Record<string, unknown>; verdict: Verdict; rules: string[]; reasons: string[] }[];
  explanation: string;
  defence: string;
}

export interface PhishSim {
  id: string;
  sender: string;
  subject: string;
  body: string;
  difficulty: string;
  role: string;
  flag_options: { id: string; label: string }[];
}

export interface PhishGrade {
  correct: boolean;
  is_phish: boolean;
  score: number;
  found: { id: string; label: string; explanation: string }[];
  missed: { id: string; label: string; explanation: string }[];
  false_alarms: string[];
  lesson: string;
}

export interface Overview {
  risk_score: number;
  risk_label: "low" | "moderate" | "high" | "critical";
  risk_breakdown: Record<string, number>;
  counts: {
    sessions: number;
    decisions: number;
    blocked: number;
    held_for_approval: number;
    allowed: number;
    hostile_context: number;
    anomalies: number;
    open_incidents: number;
    pending_approvals: number;
    quarantined_agents: number;
  };
  top_open_severity: Risk;
  resistance_score: number | null;
  compliance_coverage: number;
  audit_chain: { valid: boolean; length: number; head?: string | null };
  engine: { llm: boolean; providers: string[]; database: "sqlite" | "postgresql" };
}

export interface AuditEvent {
  id: number;
  ts: number;
  type: string;
  session_id: string | null;
  agent_id: string | null;
  payload: Record<string, unknown>;
  hash: string;
}

export interface DemoStep {
  step: number;
  module: string;
  title: string;
  result: Record<string, unknown>;
}
