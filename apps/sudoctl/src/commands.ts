// sudoctl commands. Every command is a function of parsed args returning an
// exit code: 0 ok · 1 error · 2 usage · 3 refused (policy/approval/gate) · 4 timeout.

import { join } from "node:path";
import {
  NearRpc,
  SudoContract,
  actionCommand,
  actionTitle,
  describePolicy,
  formatCountdown,
  formatDuration,
  generateKeyMaterial,
  publicKeyToString,
  secretKeyToString,
  signerFromSecretString,
  STATE_LABEL,
  type AccessRequest,
  type PolicyInput,
  type Role,
  type Signer,
} from "../../../packages/sbc-client/src/index.ts";
import { CapabilityError, SudoAgent, parseDuration } from "../../../packages/sbc-agent/src/index.ts";
import { readFileSync } from "node:fs";
import { type Args, UsageError } from "./args.ts";
import { findKey, listKeys, loadConfig, resolveConfig, saveConfig, saveKey, sbcHome, type Resolved } from "./config.ts";
import { ago, c, clock, mark, stateColor, table, time } from "./ui.ts";

export interface Ctx {
  args: Args;
  env: NodeJS.ProcessEnv;
  out: (s?: string) => void;
  err: (s?: string) => void;
}

export type Command = { summary: string; usage: string; run: (ctx: Ctx) => Promise<number> };

const VERBS: Record<string, string> = { restart: "service.restart", status: "service.status", logs: "logs.read" };

function cfg(ctx: Ctx): Resolved {
  return resolveConfig(loadConfig(), ctx.env, { contract: ctx.args.flag("contract"), rpc: ctx.args.flag("rpc"), relay: ctx.args.flag("relay") });
}

function contractOf(r: Resolved): SudoContract {
  return new SudoContract(r.contract, new NearRpc(r.rpc));
}

async function signerFor(r: Resolved, roles: Role[], as?: string): Promise<{ signer: Signer; principal: string; role: Role }> {
  const k = findKey(roles, r.contract, as);
  return { signer: await signerFromSecretString(r.contract, k.private_key), principal: k.principal, role: k.role };
}

function agentFor(r: Resolved, as?: string): SudoAgent {
  const k = findKey(["Agent"], r.contract, as);
  return new SudoAgent({ contractId: r.contract, rpcUrl: r.rpc, relayUrl: r.relay, agentSecretKey: k.private_key, stateDir: sbcHome() });
}

function requestId(ctx: Ctx, i = 0): number {
  const v = ctx.args.pos(i, "request id");
  const n = Number(v.replace(/^#/, ""));
  if (!Number.isInteger(n) || n < 0) throw new UsageError(`"${v}" is not a request id`);
  return n;
}

function actionFrom(ctx: Ctx, offset = 0): string {
  const verb = ctx.args.pos(offset, "restart|status|logs");
  const target = ctx.args.pos(offset + 1, "service");
  const kind = VERBS[verb];
  if (!kind) throw new UsageError(`unknown action "${verb}" (use restart, status or logs)`);
  return `${kind}:${target}`;
}

function printJson(ctx: Ctx, v: unknown): number {
  ctx.out(JSON.stringify(v, null, 2));
  return 0;
}

function reviewLink(r: Resolved, id: number): string | null {
  return r.console ? `${r.console.replace(/\/+$/, "")}/#/console/requests/${id}` : null;
}

/** Narrate the state changes of a capability until it is usable. */
async function follow(ctx: Ctx, r: Resolved, agent: SudoAgent, id: number): Promise<number> {
  const cap = agent.capability(id);
  try {
    const final = await cap.wait({
      onState: (x) => {
        if (x.state === "PendingApproval") {
          ctx.out(`${mark.wait} Waiting for approval — policy ${c.bold(x.policy_id ?? "?")} requires ${x.required_approvals} human approval${x.required_approvals === 1 ? "" : "s"}`);
          const link = reviewLink(r, id);
          if (link) ctx.out(`  ${c.dim("Review:")} ${link}`);
        } else if (x.state === "Signing") {
          ctx.out(`${mark.wait} Requesting threshold signature from the NEAR MPC network…`);
        }
      },
    });
    const meta = agent.sessionMeta(id);
    ctx.out(`${mark.ok} Certificate issued — serial ${final.id}, valid until ${clock(final.valid_before * 1000)} (${formatDuration(final.granted_duration_secs)}), ${final.max_uses === 1 ? "1 use" : `${final.max_uses} uses`}`);
    ctx.out(`  ${c.dim("Run:")}  sudoctl exec ${id} -- ${actionCommand(meta?.action ?? final.action)}`);
    return 0;
  } catch (e) {
    if (e instanceof CapabilityError) {
      ctx.err(`${mark.fail} ${STATE_LABEL[e.state] ?? e.state}${e.stateReason ? `: ${e.stateReason}` : ""}`);
      for (const ch of e.failedChecks) ctx.err(`  ${mark.fail} ${ch.name.padEnd(11)} ${ch.detail}`);
      return 3;
    }
    throw e;
  }
}

function checkMark(r: AccessRequest, name: string, ok: boolean): string {
  if (name === "approval" && ok) {
    if (r.state === "PendingApproval" && r.approvals.length < r.required_approvals) return mark.wait;
  }
  return ok ? mark.ok : mark.fail;
}

function renderRequest(ctx: Ctx, r: AccessRequest) {
  ctx.out(`${c.bold(`#${r.id}`)}  ${actionTitle(r.action)} on ${c.bold(r.resource_id)}  ${stateColor(r.state)}`);
  ctx.out();
  const rows: Array<[string, string]> = [
    ["Agent", r.agent_id],
    ["Resource", `${r.resource_id} (${r.environment})`],
    ["Action", `${actionTitle(r.action)}  ${c.dim(actionCommand(r.action))}`],
    ["Window", `${formatDuration(r.granted_duration_secs || r.requested_duration_secs)}${r.granted_duration_secs && r.granted_duration_secs < r.requested_duration_secs ? c.dim(` (requested ${formatDuration(r.requested_duration_secs)})`) : ""}`],
    ["Uses", `${r.uses} / ${r.max_uses}`],
    ["Reason", r.reason || "—"],
    ["Policy", r.policy_id ? `${r.policy_id} v${r.policy_version}` : "—"],
  ];
  if (r.state === "Active") rows.push(["Remaining", formatCountdown(r.valid_before * 1000 - Date.now())]);
  if (r.valid_before) rows.push(["Valid", `${clock(r.valid_after * 1000)} → ${clock(r.valid_before * 1000)}`]);
  if (r.state_reason) rows.push(["Note", r.state_reason]);
  if (r.denied_attempts) rows.push(["Denied", `${r.denied_attempts} attempt${r.denied_attempts === 1 ? "" : "s"} outside scope`]);
  for (const [k, v] of rows) ctx.out(`  ${c.dim(k.padEnd(10))} ${v}`);
  if (r.checks.length) {
    ctx.out();
    ctx.out(c.dim("  POLICY EVALUATION"));
    for (const ch of r.checks) ctx.out(`  ${checkMark(r, ch.name, ch.ok)} ${ch.name.padEnd(11)} ${ch.detail}`);
  }
  if (r.approvals.length || r.required_approvals) {
    ctx.out();
    ctx.out(c.dim(`  APPROVALS ${r.approvals.length}/${r.required_approvals}`));
    for (const a of r.approvals) ctx.out(`  ${mark.ok} ${a.approver_id}  ${c.dim(time(a.at_ms))}${a.max_duration_secs ? c.dim(`  narrowed to ${formatDuration(a.max_duration_secs)}`) : ""}`);
  }
  if (r.events.length) {
    ctx.out();
    ctx.out(c.dim("  TIMELINE"));
    for (const e of r.events) {
      const m = /denied|revoked|failed|expired/.test(e.kind) ? mark.fail : /allowed|issued|granted|used/.test(e.kind) ? mark.ok : mark.info;
      ctx.out(`  ${m} ${c.dim(clock(e.at_ms))} ${e.kind.padEnd(22)} ${c.dim(e.actor)}  ${e.detail}`);
    }
  }
  if (r.certificate) {
    ctx.out();
    ctx.out(c.dim("  CERTIFICATE (public by design — useless without the agent's ephemeral key)"));
    ctx.out(`  ${r.certificate.slice(0, 96)}…`);
  }
}

// ------------------------------------------------------------------ commands

export const commands: Record<string, Command> = {
  init: {
    summary: "Point sudoctl at a policy contract",
    usage: "sudoctl init --contract <account> [--rpc <url>] [--relay <url>] [--console <url>]",
    async run(ctx) {
      const cur = loadConfig();
      const next = {
        ...cur,
        contract: ctx.args.required("contract", "the policy contract account id"),
        rpc: ctx.args.flag("rpc") ?? cur.rpc,
        relay: ctx.args.flag("relay") ?? cur.relay,
        console: ctx.args.flag("console") ?? cur.console,
      };
      const overview = await new SudoContract(next.contract, new NearRpc(next.rpc ?? undefined)).overview();
      saveConfig(next);
      ctx.out(`${mark.ok} Using ${c.bold(next.contract)} (owner ${overview.config.owner}, MPC ${overview.config.mpc_contract} domain ${overview.config.mpc_domain_id})`);
      ctx.out(`  ${overview.resource_count} resources · ${overview.agent_count} agents · ${overview.policy_count} policies · audit seq ${overview.audit_seq}`);
      ctx.out(`  ${c.dim("config:")} ${join(sbcHome(), "config.json")}`);
      return 0;
    },
  },

  enroll: {
    summary: "Redeem a one-time enrollment token and create this machine's key",
    usage: "sudoctl enroll --token <ed25519:…>",
    async run(ctx) {
      const r = cfg(ctx);
      const token = await signerFromSecretString(r.contract, ctx.args.required("token"));
      const k = await generateKeyMaterial();
      const pk = publicKeyToString(k.publicKey);
      ctx.out(`${mark.info} Generated a new Ed25519 key ${c.dim(pk)}`);
      const res = await contractOf(r).completeEnrollment(token, pk);
      if (!res?.ok || !res.role) {
        ctx.err(`${mark.fail} ${res?.message ?? "enrollment failed"}`);
        return 3;
      }
      const path = saveKey({ account_id: r.contract, public_key: pk, private_key: secretKeyToString(k), role: res.role, principal: res.principal, created_at_ms: Date.now() });
      ctx.out(`${mark.ok} Enrolled as ${c.bold(res.role)} ${c.bold(res.principal)}. The token is burned.`);
      ctx.out(`  ${c.dim("key:")} ${path} (never leaves this machine; it can only call ${res.role === "Agent" ? "request_access, cancel_request" : "approve, deny, revoke"})`);
      return 0;
    },
  },

  whoami: {
    summary: "Show the identities enrolled on this machine",
    usage: "sudoctl whoami [--json]",
    async run(ctx) {
      const r = cfg(ctx);
      const ct = contractOf(r);
      const keys = listKeys().filter((k) => k.account_id === r.contract);
      const rows = await Promise.all(keys.map(async (k) => ({ ...k, onchain: (await ct.whoami(k.public_key)).binding })));
      if (ctx.args.bool("json")) return printJson(ctx, rows.map(({ private_key: _p, ...x }) => x));
      if (!rows.length) {
        ctx.out(`No identities for ${r.contract}. Ask an admin for a token, then: sudoctl enroll --token <token>`);
        return 0;
      }
      ctx.out(table(["ROLE", "PRINCIPAL", "ON-CHAIN", "KEY"], rows.map((x) => [x.role, x.principal, x.onchain ? `${mark.ok} ${x.onchain.role}` : `${mark.fail} not bound`, x.public_key.slice(0, 20) + "…"])));
      return 0;
    },
  },

  resources: {
    summary: "List enrolled resources",
    usage: "sudoctl resources [--json]",
    async run(ctx) {
      const rs = await contractOf(cfg(ctx)).resources();
      if (ctx.args.bool("json")) return printJson(ctx, rs);
      ctx.out(table(["ID", "ENV", "STATUS", "SERVICES", "GATE", "LAST SEEN"], rs.map((x) => [x.id, x.environment, x.status === "Active" ? c.green(x.status) : c.yellow(x.status), x.services.join(", "), x.gate_version ?? (x.gate_key ? "enrolled" : "—"), ago(x.last_seen_ms)])));
      return 0;
    },
  },

  agents: {
    summary: "List registered agents and their access history",
    usage: "sudoctl agents [--json]",
    async run(ctx) {
      const as = await contractOf(cfg(ctx)).agents();
      if (ctx.args.bool("json")) return printJson(ctx, as);
      ctx.out(table(["ID", "LABEL", "OWNER", "STATUS", "REQUESTS", "APPROVED", "REJECTED", "ACTIONS ✓", "DENIED AT GATE"], as.map((a) => [a.id, a.label, a.owner, a.status, String(a.stats.requests), String(a.stats.approved + a.stats.auto_approved), String(a.stats.rejected + a.stats.denied), String(a.stats.actions_allowed), a.stats.actions_denied ? c.red(String(a.stats.actions_denied)) : "0"])));
      return 0;
    },
  },

  policies: {
    summary: "List policies as plain sentences",
    usage: "sudoctl policies [--json]",
    async run(ctx) {
      const ps = await contractOf(cfg(ctx)).policies();
      if (ctx.args.bool("json")) return printJson(ctx, ps);
      for (const p of ps) {
        ctx.out(`${c.bold(p.id)} ${c.dim(`v${p.version} · ${p.status} · ${p.effect}`)}  ${p.name}`);
        ctx.out(`  ${describePolicy(p)}`);
      }
      if (!ps.length) ctx.out("No policies. Nothing is allowed until a policy grants it.");
      return 0;
    },
  },

  ca: {
    summary: "Print an environment's SSH CA public key (for TrustedUserCAKeys)",
    usage: "sudoctl ca <environment>",
    async run(ctx) {
      const env = ctx.args.pos(0, "environment");
      const line = await contractOf(cfg(ctx)).ca(env);
      if (!line) {
        ctx.err(`${mark.fail} environment ${env} has no CA key yet (add it with \`sudoctl admin env add ${env}\`)`);
        return 1;
      }
      ctx.out(line);
      return 0;
    },
  },

  request: {
    summary: "Request one capability (an exact action, on one resource, for a bounded time)",
    usage: 'sudoctl request <restart|status|logs> <service> --on <resource> --for 10m [--uses 1] --reason "…" [--evidence "label=value"]… [--wait]',
    async run(ctx) {
      const r = cfg(ctx);
      const action = actionFrom(ctx);
      const resource = ctx.args.required("on", "resource id");
      const duration = parseDuration(ctx.args.required("for", "e.g. 10m"));
      const uses = ctx.args.int("uses") ?? 1;
      const reason = ctx.args.required("reason", "why the agent needs this");
      const evidence = ctx.args.all("evidence").map((e) => {
        const i = e.indexOf("=");
        if (i <= 0) throw new UsageError(`--evidence "${e}" must look like "label=value"`);
        return { label: e.slice(0, i).trim(), value: e.slice(i + 1).trim() };
      });
      const agent = agentFor(r, ctx.args.flag("as"));
      ctx.out(`${mark.info} Evaluating policy for ${c.bold(actionTitle(action))} on ${c.bold(resource)} for ${formatDuration(duration)}…`);
      const sim = await agent.simulate({ resource, action, duration, uses });
      if (sim.outcome === "rejected" && !ctx.args.bool("submit-anyway")) {
        ctx.err(`${mark.fail} Policy would reject this request${sim.policy_name ? ` (closest policy: ${sim.policy_name})` : ""}:`);
        for (const ch of sim.checks) ctx.err(`  ${ch.ok ? mark.ok : mark.fail} ${ch.name.padEnd(11)} ${ch.detail}`);
        ctx.err(c.dim("  Nothing was submitted. Use --submit-anyway to record the attempt on-chain."));
        return 3;
      }
      ctx.out(`  ${mark.ok} ${sim.outcome === "auto_approved" ? "policy approves automatically" : `needs ${sim.required_approvals} human approval${sim.required_approvals === 1 ? "" : "s"}`} (${sim.policy_name ?? sim.policy_id})`);
      if (!r.relay && evidence.length) ctx.err(c.yellow("  no relay configured: evidence stays local and only the short reason goes on-chain"));
      const cap = await agent.request({ resource, action, duration, uses, reason, evidence });
      ctx.out(`${mark.ok} Request ${c.bold(`#${cap.id}`)} recorded on ${r.contract}`);
      if (!ctx.args.bool("wait")) {
        ctx.out(`  ${c.dim("Next:")} sudoctl wait ${cap.id}`);
        return 0;
      }
      return follow(ctx, r, agent, cap.id);
    },
  },

  wait: {
    summary: "Wait until a capability is usable (or ends)",
    usage: "sudoctl wait <id>",
    async run(ctx) {
      const r = cfg(ctx);
      return follow(ctx, r, agentFor(r, ctx.args.flag("as")), requestId(ctx));
    },
  },

  status: {
    summary: "Show a request: policy evaluation, approvals, timeline",
    usage: "sudoctl status <id> [--json]",
    async run(ctx) {
      const req = await contractOf(cfg(ctx)).request(requestId(ctx));
      if (!req) {
        ctx.err(`${mark.fail} no such request`);
        return 1;
      }
      if (ctx.args.bool("json")) return printJson(ctx, req);
      renderRequest(ctx, req);
      return 0;
    },
  },

  exec: {
    summary: "Run the approved action on the resource over SSH",
    usage: "sudoctl exec <id> [--host user@host:port] -- <command…>",
    async run(ctx) {
      const r = cfg(ctx);
      const id = requestId(ctx);
      if (!ctx.args.rest.length) throw new UsageError("give the command after --, e.g. sudoctl exec 41 -- sudo systemctl restart checkout-api");
      const agent = agentFor(r, ctx.args.flag("as"));
      const meta = agent.sessionMeta(id);
      const host = ctx.args.flag("host") ?? (meta ? r.hosts[meta.resource] : undefined);
      if (!host) throw new UsageError(`no address for ${meta?.resource ?? "this resource"}: pass --host user@host:port (addresses are kept off-chain in ~/.sbc/config.json "hosts")`);
      const res = await agent.capability(id).exec(ctx.args.rest, host, { onStdout: (s) => process.stdout.write(s), onStderr: (s) => process.stderr.write(s) });
      return res.exitCode;
    },
  },

  release: {
    summary: "Give a capability back before it expires",
    usage: "sudoctl release <id>",
    async run(ctx) {
      const r = cfg(ctx);
      const id = requestId(ctx);
      await agentFor(r, ctx.args.flag("as")).capability(id).release();
      ctx.out(`${mark.ok} Released #${id}. Its certificate serial is now revoked.`);
      return 0;
    },
  },

  approvals: {
    summary: "Requests waiting for a human decision",
    usage: "sudoctl approvals [--json]",
    async run(ctx) {
      const rs = await contractOf(cfg(ctx)).requests({ states: ["PendingApproval"] });
      if (ctx.args.bool("json")) return printJson(ctx, rs);
      if (!rs.length) {
        ctx.out("Nothing is waiting for approval.");
        return 0;
      }
      ctx.out(table(["ID", "AGENT", "ACTION", "RESOURCE", "WINDOW", "USES", "POLICY", "APPROVALS", "ASKED"], rs.map((x) => [`#${x.id}`, x.agent_id, actionTitle(x.action), x.resource_id, formatDuration(x.requested_duration_secs), String(x.requested_uses), x.policy_id ?? "—", `${x.approvals.length}/${x.required_approvals}`, ago(x.created_at_ms)])));
      return 0;
    },
  },

  approve: {
    summary: "Approve a request (optionally narrowing its window)",
    usage: "sudoctl approve <id> [--for 5m] [--no-wait]",
    async run(ctx) {
      const r = cfg(ctx);
      const id = requestId(ctx);
      const ct = contractOf(r);
      const { signer, principal } = await signerFor(r, ["Approver", "Admin"], ctx.args.flag("as"));
      const narrow = ctx.args.flag("for") ? parseDuration(ctx.args.flag("for")!) : undefined;
      const before = await ct.request(id);
      if (!before) throw new UsageError(`no request #${id}`);
      ctx.out(`${mark.info} Approving ${c.bold(`#${id}`)}: ${before.agent_id} may ${actionTitle(before.action).toLowerCase()} on ${before.resource_id} for ${formatDuration(narrow ?? before.requested_duration_secs)}, ${before.requested_uses === 1 ? "once" : `${before.requested_uses} times`}`);
      await ct.approve(signer, id, narrow);
      ctx.out(`${mark.ok} Approval by ${principal} recorded`);
      if (ctx.args.bool("no-wait")) return 0;
      const deadline = Date.now() + 120_000;
      let last = "";
      while (Date.now() < deadline) {
        const x = await ct.request(id);
        if (x && x.state !== last) {
          last = x.state;
          if (x.state === "PendingApproval") ctx.out(`${mark.wait} ${x.approvals.length}/${x.required_approvals} approvals — waiting for more`);
          if (x.state === "Signing") ctx.out(`${mark.wait} Requesting threshold signature from the NEAR MPC network…`);
          if (x.state === "Active") {
            ctx.out(`${mark.ok} Certificate issued — valid until ${clock(x.valid_before * 1000)}`);
            return 0;
          }
          if (!["PendingApproval", "Signing"].includes(x.state)) {
            ctx.err(`${mark.fail} ${STATE_LABEL[x.state]}${x.state_reason ? `: ${x.state_reason}` : ""}`);
            return 3;
          }
          if (x.state === "PendingApproval" && x.approvals.length < x.required_approvals) return 0;
        }
        await new Promise((res) => setTimeout(res, 2000));
      }
      ctx.err(`${mark.wait} still ${last} — check with sudoctl status ${id}`);
      return 4;
    },
  },

  deny: {
    summary: "Deny a pending request",
    usage: 'sudoctl deny <id> --reason "…"',
    async run(ctx) {
      const r = cfg(ctx);
      const { signer } = await signerFor(r, ["Approver", "Admin"], ctx.args.flag("as"));
      await contractOf(r).deny(signer, requestId(ctx), ctx.args.flag("reason") ?? "");
      ctx.out(`${mark.ok} Denied #${requestId(ctx)}`);
      return 0;
    },
  },

  revoke: {
    summary: "Revoke a capability now (effective at the gate on the next command)",
    usage: 'sudoctl revoke <id> --reason "…"',
    async run(ctx) {
      const r = cfg(ctx);
      const { signer } = await signerFor(r, ["Approver", "Admin"], ctx.args.flag("as"));
      await contractOf(r).revoke(signer, requestId(ctx), ctx.args.flag("reason") ?? "");
      ctx.out(`${mark.ok} Revoked #${requestId(ctx)}. The gate refuses it from the next command; sshd refuses it after the next KRL sync.`);
      return 0;
    },
  },

  active: {
    summary: "Capabilities that are live right now",
    usage: "sudoctl active [--json]",
    async run(ctx) {
      const rs = await contractOf(cfg(ctx)).requests({ states: ["Active", "Signing"] });
      if (ctx.args.bool("json")) return printJson(ctx, rs);
      if (!rs.length) {
        ctx.out("No live authority. Nothing standing.");
        return 0;
      }
      ctx.out(table(["ID", "AGENT", "RESOURCE", "CAPABILITY", "REMAINING", "USES", "APPROVED BY"], rs.map((x) => [`#${x.id}`, x.agent_id, x.resource_id, actionTitle(x.action), x.state === "Active" ? formatCountdown(x.valid_before * 1000 - Date.now()) : c.yellow("issuing"), `${x.uses}/${x.max_uses}`, x.approvals.map((a) => a.approver_id).join(", ") || "policy"])));
      return 0;
    },
  },

  audit: {
    summary: "Audit trail (one request, or the most recent events)",
    usage: "sudoctl audit [<id>] [--limit 40] [--json]",
    async run(ctx) {
      const ct = contractOf(cfg(ctx));
      const limit = ctx.args.int("limit") ?? 40;
      if (ctx.args.positionals[0] !== undefined) {
        const req = await ct.request(requestId(ctx));
        if (!req) throw new UsageError("no such request");
        if (ctx.args.bool("json")) return printJson(ctx, req.events);
        ctx.out(table(["SEQ", "TIME", "EVENT", "ACTOR", "DETAIL"], req.events.map((e) => [String(e.seq), time(e.at_ms), e.kind, e.actor, e.detail])));
        return 0;
      }
      const rs = await ct.requests({ limit: 50 });
      const events = rs.flatMap((r) => r.events.map((e) => ({ ...e, request_id: r.id }))).sort((a, b) => b.seq - a.seq).slice(0, limit);
      if (ctx.args.bool("json")) return printJson(ctx, events);
      ctx.out(table(["SEQ", "TIME", "REQ", "EVENT", "ACTOR", "DETAIL"], events.map((e) => [String(e.seq), time(e.at_ms), `#${e.request_id}`, /denied|revoked|failed/.test(e.kind) ? c.red(e.kind) : e.kind, e.actor, e.detail.slice(0, 80)])));
      const o = await ct.overview();
      ctx.out(c.dim(`audit chain head ${o.audit_head.slice(0, 16)}… at seq ${o.audit_seq}`));
      return 0;
    },
  },

  simulate: {
    summary: "Dry-run a request against current policy",
    usage: "sudoctl simulate <restart|status|logs> <service> --on <resource> --for 10m [--uses N] [--agent <id>]",
    async run(ctx) {
      const r = cfg(ctx);
      const action = actionFrom(ctx);
      const agentId = ctx.args.flag("agent") ?? (await agentFor(r, ctx.args.flag("as")).agentId());
      const s = await contractOf(r).simulate({ agent_id: agentId, resource_id: ctx.args.required("on"), action, duration_secs: parseDuration(ctx.args.required("for")), uses: ctx.args.int("uses") });
      if (ctx.args.bool("json")) return printJson(ctx, s);
      const verdict = s.outcome === "rejected" ? c.red("REJECTED") : s.outcome === "auto_approved" ? c.green("AUTO-APPROVED") : c.yellow(`NEEDS ${s.required_approvals} APPROVAL${s.required_approvals === 1 ? "" : "S"}`);
      ctx.out(`${verdict}  ${s.policy_name ? c.dim(`policy ${s.policy_name}`) : ""}`);
      for (const ch of s.checks) ctx.out(`  ${ch.ok ? mark.ok : mark.fail} ${ch.name.padEnd(11)} ${ch.detail}`);
      return s.outcome === "rejected" ? 3 : 0;
    },
  },

  // ------------------------------------------------------------------ admin
  "admin env add": {
    summary: "Create an environment; the MPC network derives its SSH CA key",
    usage: "sudoctl admin env add <name>",
    async run(ctx) {
      const r = cfg(ctx);
      const name = ctx.args.pos(0, "name");
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      const ct = contractOf(r);
      await ct.addEnvironment(signer, name);
      const line = await ct.ca(name);
      ctx.out(line ? `${mark.ok} ${name}: CA key derived by NEAR MPC\n  ${line}` : `${mark.wait} ${name} created; CA key pending — check with sudoctl ca ${name}`);
      return 0;
    },
  },

  "admin agent create": {
    summary: "Register an agent identity (then issue it a token)",
    usage: 'sudoctl admin agent create <id> --label "Deploy Agent" --owner platform-team --runtime "claude-opus-5-5"',
    async run(ctx) {
      const r = cfg(ctx);
      const id = ctx.args.pos(0, "id");
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      await contractOf(r).createAgent(signer, { id, label: ctx.args.required("label"), owner: ctx.args.flag("owner") ?? "", runtime: ctx.args.flag("runtime") ?? "" });
      ctx.out(`${mark.ok} Agent ${id} registered. Next: sudoctl admin token --role agent --principal ${id}`);
      return 0;
    },
  },

  "admin approver create": {
    summary: "Register a human approver (or admin)",
    usage: 'sudoctl admin approver create <id> --label "Tobi" [--admin]',
    async run(ctx) {
      const r = cfg(ctx);
      const id = ctx.args.pos(0, "id");
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      await contractOf(r).createApprover(signer, id, ctx.args.required("label"), ctx.args.bool("admin"));
      ctx.out(`${mark.ok} ${ctx.args.bool("admin") ? "Admin" : "Approver"} ${id} registered. Next: sudoctl admin token --role ${ctx.args.bool("admin") ? "admin" : "approver"} --principal ${id}`);
      return 0;
    },
  },

  "admin resource create": {
    summary: "Register a resource and the services its gate exposes",
    usage: 'sudoctl admin resource create <id> --label "prod-web-02" --env production --services checkout-api,payments-api [--tags web]',
    async run(ctx) {
      const r = cfg(ctx);
      const id = ctx.args.pos(0, "id");
      const list = (s?: string) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : []);
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      await contractOf(r).createResource(signer, { id, label: ctx.args.flag("label") ?? id, environment: ctx.args.required("env"), tags: list(ctx.args.flag("tags")), services: list(ctx.args.required("services")) });
      ctx.out(`${mark.ok} Resource ${id} registered (pending enrollment). Next: sudoctl admin token --role gate --principal ${id}`);
      return 0;
    },
  },

  "admin resource disable": {
    summary: "Kill switch: the gate refuses every action on this resource",
    usage: "sudoctl admin resource disable <id>",
    async run(ctx) {
      const r = cfg(ctx);
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      await contractOf(r).setResourceStatus(signer, ctx.args.pos(0, "id"), "Disabled");
      ctx.out(`${mark.ok} ${ctx.args.pos(0)} disabled. Already-issued capabilities stop working at the next command.`);
      return 0;
    },
  },

  "admin token": {
    summary: "Issue a one-time enrollment token for an agent, gate, approver or admin",
    usage: "sudoctl admin token --role agent|gate|approver|admin --principal <id> [--ttl 1h] [--via-owner <owner.testnet>]",
    async run(ctx) {
      const r = cfg(ctx);
      const roleArg = ctx.args.required("role").toLowerCase();
      const roles: Record<string, Role> = { agent: "Agent", gate: "Gate", approver: "Approver", admin: "Admin" };
      const role = roles[roleArg];
      if (!role) throw new UsageError("--role must be agent, gate, approver or admin");
      const principal = ctx.args.required("principal");
      const ttl = parseDuration(ctx.args.flag("ttl") ?? "1h");
      const k = await generateKeyMaterial();
      const tokenPk = publicKeyToString(k.publicKey);
      const secret = secretKeyToString(k);
      const owner = ctx.args.flag("via-owner");
      if (owner) {
        // bootstrap: no admin key exists yet, so the owner account registers the token
        ctx.out(`Run this as the contract owner to register the token (near-cli-rs):\n`);
        ctx.out(`  near contract call-function as-transaction ${r.contract} create_enrollment json-args '${JSON.stringify({ role, principal, token_public_key: tokenPk, ttl_secs: ttl })}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as ${owner} network-config testnet sign-with-keychain send\n`);
      } else {
        const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
        await contractOf(r).createEnrollment(signer, role, principal, tokenPk, ttl);
        ctx.out(`${mark.ok} Token registered for ${role} ${c.bold(principal)} — valid ${formatDuration(ttl)}, single use.\n`);
      }
      ctx.out(c.yellow("This secret is shown once. Whoever holds it can enroll as this identity until it is used or expires."));
      ctx.out(`\n  ${secret}\n`);
      if (role === "Gate") {
        ctx.out(`On the host:\n  sudo sbc-gate enroll --contract ${r.contract} --resource ${principal} --token ${secret}`);
      } else if (role === "Agent") {
        ctx.out(`On the agent's machine:\n  sudoctl init --contract ${r.contract}\n  sudoctl enroll --token ${secret}`);
      } else {
        if (r.console) ctx.out(`In a browser (creates a non-extractable device key):\n  ${r.console.replace(/\/+$/, "")}/#/join?token=${encodeURIComponent(secret)}&contract=${encodeURIComponent(r.contract)}\n`);
        ctx.out(`Or in a terminal:\n  sudoctl enroll --token ${secret}`);
      }
      return 0;
    },
  },

  "admin policy apply": {
    summary: "Create or update a policy from a JSON file (versioned on-chain)",
    usage: "sudoctl admin policy apply <policy.json>",
    async run(ctx) {
      const r = cfg(ctx);
      const p = JSON.parse(readFileSync(ctx.args.pos(0, "policy.json"), "utf8")) as PolicyInput;
      ctx.out(`${mark.info} ${describePolicy(p)}`);
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      const v = await contractOf(r).upsertPolicy(signer, p);
      if (v === 0) {
        const pending = (await contractOf(r).policyProposals()).filter((x) => x.policy.id === p.id).pop();
        ctx.out(`${mark.info} Proposed. This contract requires an admin quorum for policy changes; another admin must run:\n  sudoctl admin policy confirm ${pending?.id ?? "<proposal id>"}`);
      } else {
        ctx.out(`${mark.ok} Policy ${p.id} is now version ${v}`);
      }
      return 0;
    },
  },

  "admin policy proposals": {
    summary: "Policy changes waiting for the admin quorum",
    usage: "sudoctl admin policy proposals [--json]",
    async run(ctx) {
      const r = cfg(ctx);
      const props = await contractOf(r).policyProposals();
      if (ctx.args.bool("json")) {
        ctx.out(JSON.stringify(props, null, 2));
        return 0;
      }
      if (!props.length) ctx.out("No pending policy changes.");
      for (const x of props) {
        ctx.out(`#${x.id}  ${x.policy.id}  approved by ${x.approvals.join(", ")}  expires ${new Date(x.expires_at_ms).toISOString()}\n    ${describePolicy(x.policy)}`);
      }
      return 0;
    },
  },

  "admin policy confirm": {
    summary: "Agree to a pending policy change (counts toward the admin quorum)",
    usage: "sudoctl admin policy confirm <proposal-id>",
    async run(ctx) {
      const r = cfg(ctx);
      const id = Number(ctx.args.pos(0, "proposal-id"));
      const props = await contractOf(r).policyProposals();
      const x = props.find((p) => p.id === id);
      if (!x) {
        ctx.err(`no pending proposal #${id}`);
        return 1;
      }
      ctx.out(`${mark.info} ${describePolicy(x.policy)}`);
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      const v = await contractOf(r).confirmPolicy(signer, id);
      ctx.out(v ? `${mark.ok} Quorum met: policy ${x.policy.id} is now version ${v}` : `${mark.ok} Confirmed; still waiting for more admins`);
      return 0;
    },
  },

  "admin policy disable": {
    summary: "Disable a policy (requests stop matching it immediately)",
    usage: "sudoctl admin policy disable <id>",
    async run(ctx) {
      const r = cfg(ctx);
      const { signer } = await signerFor(r, ["Admin"], ctx.args.flag("as"));
      await contractOf(r).setPolicyStatus(signer, ctx.args.pos(0, "id"), "Suspended");
      ctx.out(`${mark.ok} Policy ${ctx.args.pos(0)} disabled`);
      return 0;
    },
  },
};

export const ADMIN_HELP = `Admin commands need an Admin key on this machine (sudoctl enroll --token …).

Bootstrapping the very first admin (once per deployment) is done by the
contract OWNER account with near-cli-rs, because no admin key exists yet:

  1. near contract call-function as-transaction <contract> create_approver \\
       json-args '{"id":"<you>","label":"<Your Name>","is_admin":true}' \\
       prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \\
       sign-as <owner> network-config testnet sign-with-keychain send
  2. sudoctl admin token --role admin --principal <you> --via-owner <owner>
       (prints the create_enrollment call for the owner, and the one-time secret)
  3. sudoctl enroll --token <secret>      # or open the console join link

After that, every admin action is signed by your scoped admin key, never by
the owner's full-access key.`;
