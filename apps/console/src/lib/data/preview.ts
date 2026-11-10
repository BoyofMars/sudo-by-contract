// PREVIEW — an in-memory simulation of the policy contract's state machine,
// used when no contract is configured. Nothing here touches a network. The
// UI labels every preview surface as simulated.
//
// It is deliberately faithful: requests are evaluated with the TS mirror of
// the contract's policy logic, certificates are real OpenSSH certificate
// encodings (signed by a throwaway in-browser key standing in for the NEAR
// MPC network), and approve/revoke walk Signing → Active → Exhausted/Revoked.

import {
  b64encode,
  concat,
  generateKeyMaterial,
  hexEncode,
  publicKeyToString,
  secretKeyToString,
  sha256,
  splitAction,
  utf8,
  type AccessRequest,
  type Agent,
  type AgentStats,
  type Approver,
  type EnrollResult,
  type Environment,
  type KeyBinding,
  type Overview,
  type Policy,
  type PolicyInput,
  type PolicyProposal,
  type RequestEvent,
  type RequestState,
  type Resource,
  type ResourceStatus,
  type Role,
  type SimulateResult,
  type Status,
} from "@sbc/client";
import { evaluate, validatePolicy } from "../policyEval.ts";
import type { ContextDocument, ContextRecord, GateReport } from "../relay.ts";
import type { DataSource, EnrollmentToken, Identity, RelayState, RequestQuery } from "./source.ts";

const MIN = 60_000;
const HOUR = 60 * MIN;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------ cert encoding

function u32(n: number) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}
function u64(n: number) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  return b;
}
function str(x: Uint8Array | string) {
  const b = typeof x === "string" ? utf8.encode(x) : x;
  return concat(u32(b.length), b);
}

async function buildCert(ca: CryptoKeyPair, caPub: Uint8Array, r: AccessRequest, subject: Uint8Array): Promise<string> {
  const principals = str(`sbc-${r.resource_id}`);
  const crit = concat(str("force-command"), str(str("/usr/local/sbin/sbc-gate")));
  const tbs = concat(
    str("ssh-ed25519-cert-v01@openssh.com"),
    str(crypto.getRandomValues(new Uint8Array(32))),
    str(subject),
    u64(r.id),
    u32(1),
    str(`sbc cap=${r.id} agent=${r.agent_id} res=${r.resource_id}`),
    str(principals),
    u64(r.valid_after),
    u64(r.valid_before),
    str(crit),
    str(new Uint8Array()),
    str(new Uint8Array()),
    str(concat(str("ssh-ed25519"), str(caPub))),
  );
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, ca.privateKey, tbs as BufferSource));
  const blob = concat(tbs, str(concat(str("ssh-ed25519"), str(sig))));
  return `ssh-ed25519-cert-v01@openssh.com ${b64encode(blob)} sbc-cap-${r.id}`;
}

function sshPubLine(pk: Uint8Array, comment: string) {
  return `ssh-ed25519 ${b64encode(concat(str("ssh-ed25519"), str(pk)))} ${comment}`;
}

// -------------------------------------------------------------------- seeds

const RATIONALE =
  "Checkout error rate increased from 1.2% to 18%. checkout-api stopped responding after deployment #1842. I am requesting one restart of the service.";

const HERO_CONTEXT: ContextDocument = {
  rationale: RATIONALE,
  evidence: [
    { label: "Checkout error rate (5m)", value: "1.2% → 18.0%" },
    { label: "Last deployment", value: "#1842 to prod-web-02, 6 minutes ago" },
    { label: "Health check", value: "GET /health timed out after 5s (3 of 3 probes)" },
    { label: "Process", value: "checkout-api running, event loop blocked; no OOM, disk 41%" },
  ],
  links: [{ label: "Checkout latency dashboard", url: "https://grafana.example.com/d/checkout" }],
};

function emptyStats(): AgentStats {
  return { requests: 0, auto_approved: 0, approved: 0, denied: 0, rejected: 0, revoked: 0, actions_allowed: 0, actions_denied: 0 };
}

interface Line {
  seq: number;
  line: string;
}

export class PreviewSource implements DataSource {
  readonly mode = "preview" as const;
  readonly contractId = "preview.sudo-by-contract";
  readonly rpcUrl = "simulated";
  readonly relayUrl = "simulated";
  readonly network = "preview" as const;

  private ready: Promise<void>;
  private ca!: CryptoKeyPair;
  private caPub!: Uint8Array;
  private agentsM = new Map<string, Agent>();
  private approversM = new Map<string, Approver>();
  private resourcesM = new Map<string, Resource>();
  private policiesM = new Map<string, Policy>();
  private history = new Map<string, Policy>();
  private envs = new Map<string, Environment>();
  private reqs: AccessRequest[] = [];
  private contexts = new Map<string, ContextRecord>();
  private reports: GateReport[] = [];
  private tokens = new Map<string, { role: Role; principal: string; expires: number }>();
  private lines: Line[] = [];
  private seq = 0;
  private revocations = 0;
  private listeners = new Set<(e: { type: "changed" }) => void>();
  private identityBinding: KeyBinding = { role: "Admin", principal: "tobi", added_at_ms: Date.now() - 30 * 24 * HOUR, enrolls_as: null, expires_at_ms: null };

  constructor() {
    this.ready = this.seed();
  }

  private notify() {
    for (const l of this.listeners) l({ type: "changed" });
  }

  private audit(kind: string, actor: string, data: Record<string, unknown>, at = Date.now()) {
    this.seq += 1;
    this.lines.push({ seq: this.seq, line: JSON.stringify({ standard: "sudo-by-contract", version: "1.0.0", event: kind, data: [{ ...data, seq: this.seq, at_ms: at, actor }] }) });
    return this.seq;
  }

  private ev(r: AccessRequest, kind: string, actor: string, detail: string, at = Date.now()) {
    const seq = this.audit(kind, actor, { request_id: r.id, agent_id: r.agent_id, resource_id: r.resource_id, action: r.action, state: r.state, detail }, at);
    const e: RequestEvent = { seq, at_ms: at, kind, actor, detail };
    r.events.push(e);
  }

  // ---------------------------------------------------------------- seed

  private async seed() {
    this.ca = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
    this.caPub = new Uint8Array(await crypto.subtle.exportKey("raw", this.ca.publicKey));
    const now = Date.now();
    const old = now - 40 * 24 * HOUR;

    this.envs.set("production", { name: "production", path: "sbc/ssh-user-ca/v1/production", ca_public_key: b64encode(this.caPub), ca_public_key_ssh: sshPubLine(this.caPub, "sbc-ca:production"), created_at_ms: old });
    this.envs.set("staging", { name: "staging", path: "sbc/ssh-user-ca/v1/staging", ca_public_key: b64encode(this.caPub), ca_public_key_ssh: sshPubLine(this.caPub, "sbc-ca:staging"), created_at_ms: old });

    const key = async () => publicKeyToString((await generateKeyMaterial()).publicKey);
    const approvers: Approver[] = [
      { id: "tobi", label: "Tobi", is_admin: true, keys: [await key(), await key()], status: "Active", created_at_ms: old },
      { id: "oncall-sre", label: "On-call SRE", is_admin: false, keys: [await key()], status: "Active", created_at_ms: old },
      { id: "maya", label: "Maya Okafor", is_admin: false, keys: [await key()], status: "Active", created_at_ms: old + 3 * 24 * HOUR },
    ];
    approvers.forEach((a) => this.approversM.set(a.id, a));

    const agents: Agent[] = [
      { id: "deploy-agent", label: "Deploy Agent", owner: "platform-team", runtime: "claude-opus-5-5 · Agent SDK", keys: [await key()], status: "Active", created_at_ms: old, stats: emptyStats() },
      { id: "log-triage", label: "Log Triage Agent", owner: "sre", runtime: "claude-sonnet-5-5 · MCP", keys: [await key()], status: "Active", created_at_ms: old + 2 * 24 * HOUR, stats: emptyStats() },
      { id: "ci-release-bot", label: "CI Release Bot", owner: "release-eng", runtime: "github-actions", keys: [await key()], status: "Active", created_at_ms: old + 9 * 24 * HOUR, stats: emptyStats() },
    ];
    agents.forEach((a) => this.agentsM.set(a.id, a));

    const res = (id: string, environment: string, services: string[], tags: string[], status: ResourceStatus = "Active"): Resource => ({
      id, label: id, environment, tags, services, principal: `sbc-${id}`,
      gate_key: status === "Pending" ? null : publicKeyToString(crypto.getRandomValues(new Uint8Array(32))),
      gate_version: status === "Pending" ? null : "0.1.0",
      host_fingerprint: status === "Pending" ? null : "SHA256:" + b64encode(crypto.getRandomValues(new Uint8Array(32))).slice(0, 43),
      status, created_at_ms: old, enrolled_at_ms: status === "Pending" ? null : old + HOUR,
      last_seen_ms: status === "Pending" ? null : now - Math.floor(Math.random() * 4 * MIN),
    });
    [
      res("prod-web-02", "production", ["checkout-api", "payments-api", "nginx", "sshd"], ["web"]),
      res("prod-web-03", "production", ["checkout-api", "nginx"], ["web"]),
      res("staging-api", "staging", ["api", "worker"], ["api"]),
      res("prod-db-01", "production", ["postgres"], ["db"], "Pending"),
    ].forEach((r) => this.resourcesM.set(r.id, r));

    const pol = async (p: PolicyInput, version: number, by: string, at: number) => {
      const full: Policy = { ...p, version, status: "Active", updated_at_ms: at, updated_by: by, hash: "" };
      full.hash = hexEncode(await sha256(utf8.encode(JSON.stringify(full))));
      this.policiesM.set(p.id, full);
      this.history.set(`${p.id}@${version}`, full);
    };
    const none = { utc_hours: null, require_source_address: false } as PolicyInput["conditions"];
    await pol({ id: "production-service-remediation", name: "Production service remediation", description: "Agents may restart customer-facing services on production after a human looks at the evidence.", effect: "Allow", subjects: { all_agents: false, agents: ["deploy-agent"] }, resources: { ids: [], environments: ["production"], tags: [] }, actions: [{ kind: "service.restart", targets: ["checkout-api", "payments-api"] }], max_duration_secs: 900, max_uses: 1, approval: { required: 1, approvers: [] }, conditions: none }, 3, "tobi", now - 9 * 24 * HOUR);
    await pol({ id: "log-inspection", name: "Log inspection", description: "Read-only journal access for triage.", effect: "Allow", subjects: { all_agents: true, agents: [] }, resources: { ids: [], environments: ["production", "staging"], tags: [] }, actions: [{ kind: "logs.read", targets: ["*"] }], max_duration_secs: 900, max_uses: 5, approval: { required: 0, approvers: [] }, conditions: none }, 1, "tobi", now - 20 * 24 * HOUR);
    await pol({ id: "status-checks", name: "Status checks", description: "", effect: "Allow", subjects: { all_agents: true, agents: [] }, resources: { ids: [], environments: ["production", "staging"], tags: [] }, actions: [{ kind: "service.status", targets: ["*"] }], max_duration_secs: 600, max_uses: 10, approval: { required: 0, approvers: [] }, conditions: none }, 1, "tobi", now - 20 * 24 * HOUR);
    await pol({ id: "never-touch-sshd", name: "Never touch sshd", description: "Restarting sshd can lock everyone out. No agent, ever.", effect: "Deny", subjects: { all_agents: true, agents: [] }, resources: { ids: [], environments: ["production", "staging"], tags: [] }, actions: [{ kind: "service.restart", targets: ["sshd"] }], max_duration_secs: 60, max_uses: 1, approval: { required: 0, approvers: [] }, conditions: none }, 1, "tobi", now - 20 * 24 * HOUR);

    // ----- history, oldest first
    const mk = async (o: { agent: string; resource: string; action: string; secs: number; uses?: number; reason: string; at: number; context?: ContextDocument }) => {
      const r = await this.createRequest(o.agent, o.resource, o.action, o.secs, o.uses ?? 1, o.reason, o.at, o.context);
      return r;
    };
    const approveAt = async (r: AccessRequest, who: string, at: number) => {
      r.approvals.push({ approver_id: who, at_ms: at, max_duration_secs: null });
      this.ev(r, "approval_granted", who, `approved (${r.approvals.length}/${r.required_approvals})`, at);
      r.granted_duration_secs = r.requested_duration_secs;
      await this.issue(r, at + 1500);
    };
    const allowed = (r: AccessRequest, at: number) => {
      r.uses += 1;
      this.ev(r, "command_allowed", r.resource_id, `${r.action} (use ${r.uses}/${r.max_uses}) session=s-${r.id}-${r.uses}`, at);
      this.report(r, "allowed", "allowed", splitAction(r.action).kind === "logs.read" ? "journalctl" : "systemctl", actionCmd(r.action), r.action, 0, at);
      if (r.uses >= r.max_uses) {
        r.state = "Exhausted";
        this.ev(r, "authorization_used", "policy", "all permitted uses consumed; capability closed", at + 50);
      }
    };

    const a = await mk({ agent: "deploy-agent", resource: "prod-web-02", action: "service.restart:payments-api", secs: 600, reason: "payments-api leaking file descriptors since 03:10; restart clears it", at: now - 26 * HOUR });
    await approveAt(a, "tobi", now - 26 * HOUR + 50_000);
    allowed(a, now - 26 * HOUR + 80_000);

    await mk({ agent: "ci-release-bot", resource: "prod-web-02", action: "service.restart:nginx", secs: 3600, reason: "post-release cache warmup", at: now - 9 * HOUR });

    const b = await mk({ agent: "log-triage", resource: "staging-api", action: "logs.read:api", secs: 900, uses: 3, reason: "triage flaky integration tests", at: now - 7 * HOUR });
    allowed(b, now - 7 * HOUR + 30_000);
    allowed(b, now - 7 * HOUR + 120_000);

    const c = await mk({ agent: "deploy-agent", resource: "prod-web-02", action: "service.restart:payments-api", secs: 600, reason: "p99 latency regression after deploy #1839", at: now - 5 * HOUR });
    await approveAt(c, "oncall-sre", now - 5 * HOUR + 120_000);
    c.state = "Revoked";
    c.revoked_by = "oncall-sre";
    c.state_reason = "Rolled back deploy #1839 instead";
    this.revocations += 1;
    this.ev(c, "authorization_revoked", "oncall-sre", "Rolled back deploy #1839 instead", now - 5 * HOUR + 200_000);

    const d = await mk({ agent: "deploy-agent", resource: "prod-web-03", action: "service.restart:checkout-api", secs: 600, reason: "checkout-api on prod-web-03 failing health checks after config reload", at: now - 42 * MIN });
    await approveAt(d, "tobi", now - 41 * MIN);
    this.deniedLocal(d, "no_adapter", "cat", "sudo cat /etc/shadow", now - 39 * MIN);
    this.deniedConsume(d, "out_of_scope", "service.restart:sshd", "sudo systemctl restart sshd", now - 38 * MIN - 30_000);
    allowed(d, now - 38 * MIN);

    const e = await mk({ agent: "log-triage", resource: "prod-web-02", action: "logs.read:checkout-api", secs: 900, uses: 5, reason: "collect error signatures for incident INC-2231", at: now - 4 * MIN });
    allowed(e, now - 3 * MIN);
    allowed(e, now - 90_000);

    const h = await mk({ agent: "deploy-agent", resource: "prod-web-02", action: "service.restart:checkout-api", secs: 600, reason: RATIONALE, at: now - 50_000, context: HERO_CONTEXT });
    void h;
  }

  private report(r: AccessRequest, decision: "allowed" | "denied", code: string, program: string, redacted: string, action: string | null, exit: number | null, at: number) {
    this.reports.unshift({ resource_id: r.resource_id, request_id: r.id, decision, code, program, redacted_command: redacted, command_sha256: hexEncode(crypto.getRandomValues(new Uint8Array(32))), action, session: `s-${r.id}-${at % 10000}`, exit_code: exit, duration_ms: exit === null ? null : 380 + (at % 900), at_ms: at });
  }

  private deniedLocal(r: AccessRequest, code: string, program: string, cmd: string, at: number) {
    r.denied_attempts += 1;
    this.ev(r, "command_denied", r.resource_id, `${code}: attempted \`${program}\` sha256=${hexEncode(crypto.getRandomValues(new Uint8Array(8)))}`, at);
    this.report(r, "denied", code, program, cmd, null, null, at);
  }

  private deniedConsume(r: AccessRequest, code: string, action: string, cmd: string, at: number) {
    r.denied_attempts += 1;
    const msg = code === "out_of_scope" ? `capability permits only ${r.action}` : code;
    this.ev(r, "command_denied", r.resource_id, `${code}: attempted ${action} (${msg}) session=s-${r.id}`, at);
    this.report(r, "denied", code, "systemctl", cmd, action, null, at);
  }

  private async createRequest(agentId: string, resourceId: string, action: string, secs: number, uses: number, reason: string, at: number, context?: ContextDocument): Promise<AccessRequest> {
    const agent = this.agentsM.get(agentId)!;
    const resource = this.resourcesM.get(resourceId)!;
    const km = await generateKeyMaterial();
    let contextHash: string | null = null;
    if (context) {
      const raw = JSON.stringify(context);
      contextHash = hexEncode(await sha256(utf8.encode(raw)));
      this.contexts.set(contextHash, { hash: contextHash, agent_id: agentId, document: context, created_at_ms: at, raw });
    }
    const r: AccessRequest = {
      id: 1036 + this.reqs.length, agent_id: agentId, resource_id: resourceId, environment: resource.environment, action,
      requested_duration_secs: secs, requested_uses: uses, ssh_public_key: b64encode(km.publicKey), source_address: null,
      reason, context_hash: contextHash, created_at_ms: at, approval_deadline_ms: at + 15 * MIN,
      policy_id: null, policy_version: null, policy_hash: null, checks: [], required_approvals: 0, eligible_approvers: [], approvals: [],
      state: "Rejected", state_reason: null, granted_duration_secs: 0, max_uses: uses, uses: 0, denied_attempts: 0,
      valid_after: 0, valid_before: 0, pending_tbs: null, certificate: null, signed_at_ms: null, revoked_by: null, events: [],
    };
    this.ev(r, "request_created", agentId, `${action} on ${resourceId} for ${secs}s`, at);
    const { target } = splitAction(action);
    if (!resource.services.includes(target)) {
      r.checks = [{ name: "resource", ok: false, detail: `${resourceId} does not expose ${target}` }];
      r.state_reason = r.checks[0].detail;
    } else {
      const e = evaluate([...this.policiesM.values()], { agent, resource, action, durationSecs: secs, uses, sourceAddress: null, nowMs: at });
      r.checks = e.checks;
      if (e.policy) {
        r.policy_id = e.policy.id;
        r.policy_version = "version" in e.policy ? e.policy.version : 1;
        r.policy_hash = "hash" in e.policy ? e.policy.hash : null;
        r.eligible_approvers = e.policy.approval.approvers;
      }
      if (e.outcome.kind === "rejected") r.state_reason = (() => { const f = r.checks.find((c) => !c.ok); return f ? `${f.name}: ${f.detail}` : "rejected"; })();
      else if (e.outcome.kind === "approval") { r.state = "PendingApproval"; r.required_approvals = e.outcome.required; }
      else { r.state = "Signing"; r.granted_duration_secs = secs; }
    }
    const detail = r.state === "Rejected" ? r.state_reason ?? "" : r.state === "PendingApproval" ? `policy ${r.policy_id} requires ${r.required_approvals} approval(s)` : `auto-approved by policy ${r.policy_id}`;
    this.ev(r, "policy_evaluated", "policy", detail, at + 5);
    this.reqs.push(r);
    if (r.state === "Signing") {
      this.ev(r, "approval_granted", "policy", "auto-approved", at + 6);
      await this.issue(r, at + 1800, km.publicKey);
    }
    return r;
  }

  /** Signing → Active with a real (preview-CA-signed) certificate. */
  private async issue(r: AccessRequest, at: number, subject?: Uint8Array) {
    r.state = "Signing";
    r.valid_after = Math.floor((at - 1500) / 1000) - 60;
    r.valid_before = Math.floor((at - 1500) / 1000) + r.granted_duration_secs;
    this.ev(r, "credential_signing", "mpc", "requesting threshold signature (338 byte certificate body)", at - 1400);
    const sub = subject ?? Uint8Array.from(atob(r.ssh_public_key), (c) => c.charCodeAt(0));
    r.certificate = await buildCert(this.ca, this.caPub, r, sub);
    r.signed_at_ms = at;
    r.state = "Active";
    this.ev(r, "credential_issued", "mpc", `certificate serial ${r.id} valid until ${r.valid_before}`, at);
  }

  private eff(r: AccessRequest, now = Date.now()): RequestState {
    if (r.state === "Active" && now >= r.valid_before * 1000) return "Expired";
    if (r.state === "PendingApproval" && now >= r.approval_deadline_ms) return "ApprovalExpired";
    return r.state;
  }

  private view(r: AccessRequest): AccessRequest {
    return { ...r, state: this.eff(r), checks: [...r.checks], approvals: [...r.approvals], events: [...r.events] };
  }

  private stats(id: string): AgentStats {
    const s = emptyStats();
    for (const r of this.reqs) {
      if (r.agent_id !== id) continue;
      s.requests++;
      const st = this.eff(r);
      if (st === "Rejected") s.rejected++;
      if (st === "Denied") s.denied++;
      if (st === "Revoked") s.revoked++;
      if (r.approvals.length) s.approved++;
      else if (r.events.some((e) => e.kind === "approval_granted" && e.actor === "policy")) s.auto_approved++;
      s.actions_allowed += r.events.filter((e) => e.kind === "command_allowed").length;
      s.actions_denied += r.events.filter((e) => e.kind === "command_denied").length;
    }
    return s;
  }

  // ---------------------------------------------------------------- views

  async overview(): Promise<Overview> {
    await this.ready;
    let head: Uint8Array = new Uint8Array(32);
    for (const l of this.lines) head = await sha256(concat(head, utf8.encode(l.line)));
    return {
      config: {
        owner: "ops-root.testnet", mpc_contract: "v1.signer-prod.testnet", mpc_domain_id: 1, ca_version: 1, force_command: "/usr/local/sbin/sbc-gate",
        skew_secs: 60, approval_ttl_secs: 900, max_pending_per_agent: 4, max_duration_secs: 14400,
        allowance_admin: "2000000000000000000000000", allowance_approver: "1000000000000000000000000", allowance_agent: "1000000000000000000000000",
        allowance_gate: "2000000000000000000000000", allowance_enrollment: "250000000000000000000000", sign_gas_tgas: 50, callback_gas_tgas: 25, policy_quorum: 1,
      },
      environments: [...this.envs.values()],
      audit_seq: this.seq,
      audit_head: hexEncode(head),
      request_count: this.reqs.length,
      agent_count: this.agentsM.size,
      resource_count: this.resourcesM.size,
      policy_count: this.policiesM.size,
      approver_count: this.approversM.size,
      revocation_count: this.revocations,
      now_ms: Date.now(),
    };
  }

  async requests(q: RequestQuery = {}) {
    await this.ready;
    let list = [...this.reqs].reverse().map((r) => this.view(r));
    if (q.before_id !== undefined) list = list.filter((r) => r.id < q.before_id!);
    if (q.agent_id) list = list.filter((r) => r.agent_id === q.agent_id);
    if (q.resource_id) list = list.filter((r) => r.resource_id === q.resource_id);
    if (q.states) list = list.filter((r) => q.states!.includes(r.state));
    return list.slice(0, q.limit ?? 50);
  }
  async request(id: number) {
    await this.ready;
    const r = this.reqs.find((x) => x.id === id);
    return r ? this.view(r) : null;
  }
  async agents() { await this.ready; return [...this.agentsM.values()].map((a) => ({ ...a, stats: this.stats(a.id) })); }
  async approvers() { await this.ready; return [...this.approversM.values()]; }
  async resources() {
    await this.ready;
    const now = Date.now();
    return [...this.resourcesM.values()].map((r) => (r.status === "Active" && r.last_seen_ms ? { ...r, last_seen_ms: Math.max(r.last_seen_ms, now - 3 * MIN) } : { ...r }));
  }
  async policies() { await this.ready; return [...this.policiesM.values()]; }
  async policy(id: string, version?: number) { await this.ready; return (version ? this.history.get(`${id}@${version}`) : this.policiesM.get(id)) ?? null; }

  async simulate(a: { agent_id: string; resource_id: string; action: string; duration_secs: number; uses?: number; source_address?: string }): Promise<SimulateResult> {
    await this.ready;
    const agent = this.agentsM.get(a.agent_id);
    const resource = this.resourcesM.get(a.resource_id);
    if (!agent || !resource) throw new Error("unknown agent or resource");
    const { target } = splitAction(a.action);
    if (!resource.services.includes(target)) return { outcome: "rejected", policy_id: null, policy_name: null, required_approvals: 0, checks: [{ name: "resource", ok: false, detail: `${resource.id} does not expose ${target}` }] };
    const e = evaluate([...this.policiesM.values()], { agent, resource, action: a.action, durationSecs: a.duration_secs, uses: a.uses ?? 1, sourceAddress: a.source_address ?? null, nowMs: Date.now() });
    return {
      outcome: e.outcome.kind === "auto" ? "auto_approved" : e.outcome.kind === "approval" ? "needs_approval" : "rejected",
      policy_id: e.policy?.id ?? null, policy_name: e.policy?.name ?? null, required_approvals: e.policy?.approval.required ?? 0, checks: e.checks,
    };
  }

  async identity(): Promise<Identity> {
    await this.ready;
    return { publicKey: "ed25519:PreviewDeviceKeyNotARealKey11111111111111111", binding: this.identityBinding };
  }

  async relayState(): Promise<RelayState> { return "ok"; }
  async context(hash: string) { await this.ready; return this.contexts.get(hash) ?? null; }
  async gateReports(q: { request_id?: number; resource_id?: string; limit?: number }) {
    await this.ready;
    return this.reports.filter((r) => (q.request_id === undefined || r.request_id === q.request_id) && (!q.resource_id || r.resource_id === q.resource_id)).slice(0, q.limit ?? 50);
  }
  subscribe(cb: (e: { type: "changed" }) => void) {
    this.listeners.add(cb);
    return () => { this.listeners.delete(cb); };
  }

  // ---------------------------------------------------------------- writes

  private get(id: number) {
    const r = this.reqs.find((x) => x.id === id);
    if (!r) throw new Error("unknown request");
    const e = this.eff(r);
    if (e !== r.state) {
      r.state = e;
      this.ev(r, e === "Expired" ? "authorization_expired" : "approval_expired", "clock", "validity window elapsed");
    }
    return r;
  }

  async approve(id: number, maxDurationSecs?: number) {
    await this.ready;
    await sleep(700);
    const r = this.get(id);
    if (r.state !== "PendingApproval") return;
    const who = this.identityBinding.principal;
    if (r.approvals.some((a) => a.approver_id === who)) throw new Error("already approved");
    if (maxDurationSecs && (maxDurationSecs < 60 || maxDurationSecs > r.requested_duration_secs)) throw new Error("approvers can only narrow the window");
    r.approvals.push({ approver_id: who, at_ms: Date.now(), max_duration_secs: maxDurationSecs ?? null });
    this.ev(r, "approval_granted", who, maxDurationSecs ? `approved, window narrowed to ${maxDurationSecs}s (${r.approvals.length}/${r.required_approvals})` : `approved (${r.approvals.length}/${r.required_approvals})`);
    if (r.approvals.length < r.required_approvals) return this.notify();
    r.granted_duration_secs = r.approvals.reduce((acc, a) => Math.min(acc, a.max_duration_secs ?? acc), r.requested_duration_secs);
    r.state = "Signing";
    this.ev(r, "credential_signing", "mpc", "requesting threshold signature (338 byte certificate body)");
    this.notify();
    // simulated MPC latency, then issuance
    setTimeout(async () => {
      if (r.state !== "Signing") return;
      const now = Date.now();
      r.valid_after = Math.floor(now / 1000) - 60;
      r.valid_before = Math.floor(now / 1000) + r.granted_duration_secs;
      r.certificate = await buildCert(this.ca, this.caPub, r, Uint8Array.from(atob(r.ssh_public_key), (c) => c.charCodeAt(0)));
      r.signed_at_ms = now;
      r.state = "Active";
      this.ev(r, "credential_issued", "mpc", `certificate serial ${r.id} valid until ${r.valid_before}`);
      this.notify();
      this.simulateAgent(r);
    }, 3200);
  }

  /** What the Deploy Agent does with a fresh capability in the hero demo. */
  private simulateAgent(r: AccessRequest) {
    if (r.action !== "service.restart:checkout-api") return;
    setTimeout(() => {
      this.deniedLocal(r, "no_adapter", "cat", "sudo cat /etc/shadow", Date.now());
      this.notify();
    }, 14_000);
    setTimeout(() => {
      const st = this.get(r.id).state;
      if (st === "Active") {
        this.deniedConsume(r, "out_of_scope", "service.restart:sshd", "sudo systemctl restart sshd", Date.now());
      } else {
        this.deniedConsume(r, st === "Revoked" ? "revoked" : "not_active", "service.restart:sshd", "sudo systemctl restart sshd", Date.now());
      }
      this.notify();
    }, 18_000);
    setTimeout(() => {
      const cur = this.get(r.id);
      if (cur.state !== "Active") {
        this.deniedConsume(cur, cur.state === "Revoked" ? "revoked" : "not_active", cur.action, "sudo systemctl restart checkout-api", Date.now());
        return this.notify();
      }
      cur.uses += 1;
      this.ev(cur, "command_allowed", cur.resource_id, `${cur.action} (use ${cur.uses}/${cur.max_uses}) session=s-${cur.id}-live`);
      this.report(cur, "allowed", "allowed", "systemctl", "sudo systemctl restart checkout-api", cur.action, 0, Date.now());
      if (cur.uses >= cur.max_uses) {
        cur.state = "Exhausted";
        this.ev(cur, "authorization_used", "policy", "all permitted uses consumed; capability closed");
      }
      this.notify();
    }, 24_000);
  }

  async deny(id: number, reason: string) {
    await this.ready;
    await sleep(600);
    const r = this.get(id);
    if (r.state !== "PendingApproval") throw new Error("request is not awaiting approval");
    r.state = "Denied";
    r.state_reason = reason || "denied";
    this.ev(r, "approval_denied", this.identityBinding.principal, reason);
    this.notify();
  }

  async revoke(id: number, reason: string) {
    await this.ready;
    await sleep(600);
    const r = this.get(id);
    if (!["PendingApproval", "Signing", "Active"].includes(r.state)) throw new Error("nothing to revoke");
    if (r.state !== "PendingApproval") this.revocations += 1;
    r.state = "Revoked";
    r.revoked_by = this.identityBinding.principal;
    r.state_reason = reason || "revoked";
    this.ev(r, "authorization_revoked", this.identityBinding.principal, reason);
    this.notify();
  }

  async createAgent(a: { id: string; label: string; owner: string; runtime: string }) {
    await this.ready; await sleep(500);
    if (this.agentsM.has(a.id)) throw new Error("agent exists");
    this.agentsM.set(a.id, { ...a, keys: [], status: "Active", created_at_ms: Date.now(), stats: emptyStats() });
    this.audit("agent_created", this.identityBinding.principal, { agent_id: a.id });
    this.notify();
  }
  async setAgentStatus(id: string, status: Status) { await sleep(400); const a = this.agentsM.get(id); if (a) a.status = status; this.notify(); }
  async createApprover(id: string, label: string, isAdmin: boolean) {
    await sleep(500);
    if (this.approversM.has(id)) throw new Error("approver exists");
    this.approversM.set(id, { id, label, is_admin: isAdmin, keys: [], status: "Active", created_at_ms: Date.now() });
    this.notify();
  }
  async setApproverStatus(id: string, status: Status) { await sleep(400); const a = this.approversM.get(id); if (a) a.status = status; this.notify(); }
  async createResource(r: { id: string; label: string; environment: string; tags: string[]; services: string[] }) {
    await this.ready; await sleep(600);
    if (this.resourcesM.has(r.id)) throw new Error("resource exists");
    if (!this.envs.has(r.environment)) throw new Error("unknown environment; add_environment first");
    this.resourcesM.set(r.id, { ...r, principal: `sbc-${r.id}`, gate_key: null, gate_version: null, host_fingerprint: null, status: "Pending", created_at_ms: Date.now(), enrolled_at_ms: null, last_seen_ms: null });
    this.audit("resource_created", this.identityBinding.principal, { resource_id: r.id });
    this.notify();
  }
  async setResourceStatus(id: string, status: ResourceStatus) { await sleep(400); const r = this.resourcesM.get(id); if (r) r.status = status; this.notify(); }
  async addEnvironment(name: string) {
    await this.ready; await sleep(900);
    this.envs.set(name, { name, path: `sbc/ssh-user-ca/v1/${name}`, ca_public_key: b64encode(this.caPub), ca_public_key_ssh: sshPubLine(this.caPub, `sbc-ca:${name}`), created_at_ms: Date.now() });
    this.notify();
  }

  async createEnrollment(role: Role, principal: string, ttlSecs = 3600): Promise<EnrollmentToken> {
    await this.ready; await sleep(600);
    const km = await generateKeyMaterial();
    const token = secretKeyToString(km);
    this.tokens.set(token, { role, principal, expires: Date.now() + ttlSecs * 1000 });
    if (role === "Gate") {
      // simulated host: enrolls ~8s after the token is created
      setTimeout(() => {
        const r = this.resourcesM.get(principal);
        if (!r) return;
        r.gate_key = publicKeyToString(crypto.getRandomValues(new Uint8Array(32)));
        r.gate_version = "0.1.0";
        r.host_fingerprint = "SHA256:" + b64encode(crypto.getRandomValues(new Uint8Array(32))).slice(0, 43);
        r.status = "Active";
        r.enrolled_at_ms = Date.now();
        r.last_seen_ms = Date.now();
        this.tokens.delete(token);
        this.audit("enrollment_completed", principal, { role, principal });
        this.notify();
      }, 8000);
    }
    return { token, tokenPublicKey: publicKeyToString(km.publicKey), expiresAtMs: Date.now() + ttlSecs * 1000 };
  }

  async upsertPolicy(p: PolicyInput) {
    await this.ready; await sleep(700);
    const err = validatePolicy(p);
    if (err) throw new Error(err);
    const version = (this.policiesM.get(p.id)?.version ?? 0) + 1;
    const full: Policy = { ...p, version, status: "Active", updated_at_ms: Date.now(), updated_by: this.identityBinding.principal, hash: "" };
    full.hash = hexEncode(await sha256(utf8.encode(JSON.stringify(full))));
    this.policiesM.set(p.id, full);
    this.history.set(`${p.id}@${version}`, full);
    this.audit("policy_updated", this.identityBinding.principal, { policy_id: p.id, version });
    this.notify();
    return version;
  }
  async setPolicyStatus(id: string, status: Status) { await sleep(400); const p = this.policiesM.get(id); if (p) p.status = status; this.notify(); }
  // the preview runs with policy_quorum = 1: changes apply immediately
  async policyProposals(): Promise<PolicyProposal[]> { return []; }
  async confirmPolicy(): Promise<number> { throw new Error("no such proposal"); }

  async enrollDevice(token: string): Promise<EnrollResult> {
    await this.ready; await sleep(1200);
    const t = this.tokens.get(token.trim());
    if (!t) return { ok: true, role: "Approver", principal: "maya", message: "enrolled (simulated)" };
    if (t.expires < Date.now()) return { ok: false, role: null, principal: t.principal, message: "enrollment token expired" };
    this.tokens.delete(token.trim());
    return { ok: true, role: t.role, principal: t.principal, message: "enrolled (simulated)" };
  }
  async forgetDevice() { /* preview identity is fixed */ }
}

function actionCmd(action: string) {
  const { kind, target } = splitAction(action);
  if (kind === "logs.read") return `journalctl -u ${target} -n 100`;
  if (kind === "service.status") return `systemctl status ${target}`;
  return `sudo systemctl restart ${target}`;
}
