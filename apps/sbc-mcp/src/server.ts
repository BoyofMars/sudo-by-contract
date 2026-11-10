// MCP tool surface for Sudo by Contract. Transport-agnostic: `handle()` takes
// one JSON-RPC message and returns the response (or null for notifications).

import { actionCommand, actionTitle, formatDuration, type AccessRequest, type Resource, type SimulateResult } from "../../../packages/sbc-client/src/index.ts";
import { CapabilityError, TimeoutError, type ExecResult, type RequestOptions } from "../../../packages/sbc-agent/src/index.ts";

export const PROTOCOL_VERSION = "2025-06-18";

export interface McpCapability {
  state(): Promise<AccessRequest>;
  wait(o?: { timeoutMs?: number }): Promise<AccessRequest>;
  exec(command: string, target: string): Promise<ExecResult>;
  release(): Promise<void>;
}

export interface McpAgent {
  listResources(): Promise<Resource[]>;
  simulate(o: { resource: string; action: string; duration: string | number; uses?: number }): Promise<SimulateResult>;
  request(o: RequestOptions): Promise<{ id: number }>;
  capability(id: number): McpCapability;
  sessionMeta(id: number): { resource: string } | null;
}

export interface McpServerOptions {
  agent: McpAgent;
  hosts: Record<string, string>;
  consoleUrl?: string | null;
}

type Json = Record<string, unknown>;

const ACTION_SCHEMA = {
  type: "string",
  description: "Canonical action: service.restart:<unit>, service.status:<unit> or logs.read:<unit>. There is no shell action.",
  pattern: "^(service\\.restart|service\\.status|logs\\.read):[A-Za-z0-9][A-Za-z0-9_.@:-]{0,99}$",
};

export const TOOLS = [
  {
    name: "list_resources",
    description: "List the servers enrolled in Sudo by Contract and the services each one exposes to agents. Read-only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "simulate_access",
    description: "Dry-run an access request against the organisation's current policy without submitting it. Shows which checks pass or fail and whether a human must approve.",
    inputSchema: {
      type: "object",
      properties: {
        resource: { type: "string" },
        action: ACTION_SCHEMA,
        duration: { type: "string", description: "e.g. 10m" },
        uses: { type: "integer", minimum: 1, maximum: 100 },
      },
      required: ["resource", "action", "duration"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "request_capability",
    description:
      "Ask for ONE narrowly scoped, temporary capability: one action on one resource for a bounded time and number of uses. You never receive a reusable credential: a fresh key is generated locally, and a short-lived certificate bound to it is issued only if policy (and, when policy requires, a human approver) agrees. Returns immediately with the request id and policy outcome; use wait_for_capability next. Your reason and evidence are shown to the human approver but can never change the policy.",
    inputSchema: {
      type: "object",
      properties: {
        resource: { type: "string", description: "Resource id from list_resources" },
        action: ACTION_SCHEMA,
        duration: { type: "string", description: "Smallest window that suffices, e.g. 10m" },
        uses: { type: "integer", minimum: 1, maximum: 100, description: "Default 1. Ask for exactly what the task needs." },
        reason: { type: "string", maxLength: 4000, description: "Why this is needed. The first 280 characters are recorded publicly on-chain; keep secrets out." },
        evidence: { type: "array", maxItems: 20, items: { type: "object", properties: { label: { type: "string" }, value: { type: "string" } }, required: ["label", "value"] } },
      },
      required: ["resource", "action", "duration", "reason"],
      additionalProperties: false,
    },
  },
  {
    name: "capability_status",
    description: "Current state of a capability: pending approval, issuing, active (with time and uses remaining), or finished (used, expired, revoked, denied, rejected).",
    inputSchema: { type: "object", properties: { id: { type: "integer", minimum: 0 } }, required: ["id"], additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "wait_for_capability",
    description: "Block until a capability is usable or ends. A human may need to approve it, which can take minutes; if it times out, call again or report back to the user.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "integer", minimum: 0 }, timeout_seconds: { type: "integer", minimum: 5, maximum: 1800 } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "run_approved_action",
    description:
      "Run a command over SSH under an ACTIVE capability. The host's gate parses the command into a typed action and checks it with the policy contract before executing; anything outside the capability (other commands, other services, shells, after expiry or once uses are consumed) is refused, and the refusal is recorded. Report refusals honestly; do not try variations to get around them.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "integer", minimum: 0 },
        command: { type: "string", description: "e.g. sudo systemctl restart checkout-api" },
        host: { type: "string", description: "Optional user@host:port override; normally configured by the operator" },
      },
      required: ["id", "command"],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true },
  },
  {
    name: "release_capability",
    description: "Give the capability back as soon as the task is done. Its certificate serial is revoked immediately.",
    inputSchema: { type: "object", properties: { id: { type: "integer", minimum: 0 } }, required: ["id"], additionalProperties: false },
  },
];

function summarize(r: AccessRequest, consoleUrl?: string | null): Json {
  const out: Json = {
    id: r.id,
    state: r.state,
    action: r.action,
    resource: r.resource_id,
    policy: r.policy_id,
    approvals: `${r.approvals.length}/${r.required_approvals}`,
    uses: `${r.uses}/${r.max_uses}`,
  };
  if (r.state === "Active") {
    out.remaining_seconds = Math.max(0, Math.floor(r.valid_before - Date.now() / 1000));
    out.run = actionCommand(r.action);
  }
  if (r.state_reason) out.reason = r.state_reason;
  const failed = r.checks.filter((c) => !c.ok);
  if (failed.length) out.failed_checks = failed.map((c) => `${c.name}: ${c.detail}`);
  if (r.state === "PendingApproval" && consoleUrl) out.review_url = `${consoleUrl.replace(/\/+$/, "")}/#/console/requests/${r.id}`;
  return out;
}

function text(t: string, structured?: Json, isError = false) {
  return { content: [{ type: "text", text: t }], ...(structured ? { structuredContent: structured } : {}), ...(isError ? { isError: true } : {}) };
}

export function createMcpServer(o: McpServerOptions) {
  const hostFor = (id: number, override?: string) => {
    if (override) return override;
    const meta = o.agent.sessionMeta(id);
    const h = meta ? o.hosts[meta.resource] : undefined;
    if (!h) throw new Error(`no SSH address configured for ${meta?.resource ?? `capability ${id}`} (set SBC_HOSTS)`);
    return h;
  };

  async function callTool(name: string, a: any) {
    switch (name) {
      case "list_resources": {
        const rs = await o.agent.listResources();
        const list = rs.map((r) => ({ id: r.id, environment: r.environment, status: r.status, services: r.services }));
        return text(list.map((r) => `${r.id} (${r.environment}, ${r.status}): ${r.services.join(", ")}`).join("\n") || "No resources enrolled.", { resources: list });
      }
      case "simulate_access": {
        const s = await o.agent.simulate({ resource: a.resource, action: a.action, duration: a.duration, uses: a.uses });
        const lines = s.checks.map((c) => `${c.ok ? "✓" : "✕"} ${c.name}: ${c.detail}`);
        return text(`${s.outcome}${s.policy_name ? ` (policy ${s.policy_name})` : ""}\n${lines.join("\n")}`, s as unknown as Json);
      }
      case "request_capability": {
        const cap = await o.agent.request({ resource: a.resource, action: a.action, duration: a.duration, uses: a.uses ?? 1, reason: a.reason, evidence: a.evidence });
        const r = await o.agent.capability(cap.id).state();
        const s = summarize(r, o.consoleUrl);
        const next =
          r.state === "Rejected" ? "Policy rejected this request; do not retry with variations — tell the user what failed." :
          r.state === "PendingApproval" ? "A human must approve. Call wait_for_capability." : "Call wait_for_capability.";
        return text(`Request #${r.id}: ${actionTitle(r.action)} on ${r.resource_id} for ${formatDuration(r.requested_duration_secs)} → ${r.state}. ${next}`, s, r.state === "Rejected");
      }
      case "capability_status": {
        const r = await o.agent.capability(a.id).state();
        return text(`#${r.id} is ${r.state}`, summarize(r, o.consoleUrl));
      }
      case "wait_for_capability": {
        try {
          const r = await o.agent.capability(a.id).wait({ timeoutMs: (a.timeout_seconds ?? 300) * 1000 });
          return text(`#${r.id} is ACTIVE for ${Math.max(0, Math.floor(r.valid_before - Date.now() / 1000))}s, ${r.max_uses - r.uses} use(s). Run: ${actionCommand(r.action)}`, summarize(r, o.consoleUrl));
        } catch (e) {
          if (e instanceof CapabilityError && e.request) return text(`#${a.id} ended as ${e.state}${e.stateReason ? `: ${e.stateReason}` : ""}`, summarize(e.request, o.consoleUrl), true);
          if (e instanceof TimeoutError) return text(`${e.message}. A human may still be reviewing it.`, { id: a.id, timed_out: true });
          throw e;
        }
      }
      case "run_approved_action": {
        const res = await o.agent.capability(a.id).exec(a.command, hostFor(a.id, a.host));
        const refused = res.exitCode !== 0;
        const t = refused
          ? `Refused or failed (exit ${res.exitCode}). ${res.stderr.trim() || res.stdout.trim()}`
          : `OK (exit 0).${res.stdout.trim() ? `\n${res.stdout.trim()}` : ""}`;
        return text(t, { exit_code: res.exitCode, stdout: res.stdout, stderr: res.stderr, duration_ms: res.durationMs }, refused);
      }
      case "release_capability": {
        await o.agent.capability(a.id).release();
        return text(`Released #${a.id}; its certificate serial is revoked.`, { id: a.id, released: true });
      }
      default:
        return null;
    }
  }

  async function handle(msg: any): Promise<Json | null> {
    const id = msg?.id;
    const isRequest = id !== undefined && id !== null;
    const reply = (result: unknown) => ({ jsonrpc: "2.0", id, result });
    const fail = (code: number, message: string) => ({ jsonrpc: "2.0", id: isRequest ? id : null, error: { code, message } });
    if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(-32600, "invalid request");
    if (!isRequest) return null; // notifications/initialized, notifications/cancelled, ...
    switch (msg.method) {
      case "initialize":
        return reply({
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "sudo-by-contract", title: "Sudo by Contract", version: "0.1.0" },
          instructions:
            "Use these tools when a task needs to act on production infrastructure. You will never hold a reusable credential: request the narrowest capability, wait for policy/human approval, run exactly the approved action, then release it. Refusals are enforced by the host and the policy contract; report them instead of working around them.",
        });
      case "ping":
        return reply({});
      case "tools/list":
        return reply({ tools: TOOLS });
      case "tools/call": {
        const name = msg.params?.name;
        if (!TOOLS.some((t) => t.name === name)) return fail(-32602, `unknown tool ${name}`);
        try {
          return reply(await callTool(name, msg.params?.arguments ?? {}));
        } catch (e) {
          return reply(text(e instanceof Error ? e.message : String(e), undefined, true));
        }
      }
      default:
        return fail(-32601, `method not found: ${msg.method}`);
    }
  }

  return { handle };
}
