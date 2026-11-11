#!/usr/bin/env node
// Deploy Agent — the hero demo for Sudo by Contract.
//
// It notices checkout is broken, asks for exactly one restart, waits for a
// human, restarts the service, and then tries (and fails) to do more. Every
// line it prints about allowed or denied actions comes from what the host
// actually returned; nothing here simulates enforcement.
//
//   node apps/demo-agent/src/main.ts [--scenario full|restart|expiry|injection] [--force]
//
// `injection` hands the incident to a real model (Claude, via the Anthropic
// API; needs ANTHROPIC_API_KEY) with capability tools, against a host whose
// logs carry a prompt injection. See llm-agent.ts.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  actionTitle,
  formatCountdown,
  parseCertificateLine,
  type AccessRequest,
} from "../../../packages/sbc-client/src/index.ts";
import { CapabilityError, SudoAgent, type Capability, type ExecResult } from "../../../packages/sbc-agent/src/index.ts";
import { act, command, fail, indent, ok, say, sleep, step, style, thought, verdict, wait } from "./narrate.ts";
import { compromisedAct, llmAct } from "./llm-agent.ts";

const env = process.env;
const argv = process.argv.slice(2);
const flag = (name: string) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const scenario = flag("scenario") ?? "full";
const force = argv.includes("--force");

const RESOURCE = env.SBC_RESOURCE ?? "prod-web-02";
const HOST = env.SBC_HOST ?? "sbc-agent@demo-server:22";
const HEALTH = env.SBC_HEALTH_URL ?? "http://demo-server:8080/health";
const CONSOLE = env.SBC_CONSOLE_URL;
const SERVICE = env.SBC_SERVICE ?? "checkout-api";

function agentFromEnv(): SudoAgent {
  const contractId = env.SBC_CONTRACT;
  const secret = (env.SBC_AGENT_KEY || (env.SBC_AGENT_KEY_FILE ? JSON.parse(readFileSync(env.SBC_AGENT_KEY_FILE, "utf8")).private_key : ""))?.trim();
  if (!contractId || !secret) {
    say("Set SBC_CONTRACT and SBC_AGENT_KEY (or SBC_AGENT_KEY_FILE). See sandbox/README.md.");
    process.exit(2);
  }
  return new SudoAgent({
    contractId,
    rpcUrl: env.SBC_RPC,
    relayUrl: env.SBC_RELAY,
    agentSecretKey: secret,
    stateDir: env.SBC_STATE_DIR ?? join(tmpdir(), "sbc-demo-agent"),
    onWarning: (m) => say(`    ${style.yellow("!")} ${style.dim(m)}`),
  });
}

interface Health {
  healthy: boolean;
  status: number;
  body: Record<string, unknown>;
  error?: string;
}

async function probe(): Promise<Health> {
  try {
    const res = await fetch(HEALTH, { signal: AbortSignal.timeout(3000) });
    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      /* not JSON */
    }
    const healthy = res.ok && (body.status === undefined || body.status === "ok");
    return { healthy, status: res.status, body };
  } catch (e) {
    return { healthy: false, status: 0, body: {}, error: e instanceof Error ? e.message : String(e) };
  }
}

const pct = (v: unknown) => (typeof v === "number" ? `${(v * 100).toFixed(1)}%` : typeof v === "string" ? v : undefined);

let unexpected = 0;

/** Run one command and judge the outcome against what the capability should allow. */
async function attempt(cap: Capability, cmd: string, expect: "allowed" | "denied", why: string): Promise<ExecResult | null> {
  command(cmd);
  let res: ExecResult;
  try {
    res = await cap.exec(cmd, HOST, { timeoutMs: 60_000 });
  } catch (e) {
    fail(`could not run ssh: ${e instanceof Error ? e.message : e}`);
    unexpected++;
    return null;
  }
  const sshLayer = res.exitCode === 255 && /Permission denied|Certificate invalid|not yet valid|expired/i.test(res.stderr);
  if (res.exitCode === 0) {
    ok(`allowed · exit 0 · ${res.durationMs} ms`);
    if (res.stdout.trim()) indent(res.stdout.trim().split("\n").slice(-6).join("\n"));
  } else if (sshLayer) {
    fail(`${style.bold("DENIED by sshd")} during authentication (exit 255) — the gate never ran`);
    indent(res.stderr.trim());
  } else {
    fail(`${style.bold("DENIED")} · exit ${res.exitCode}`);
    indent(res.stderr.trim() || res.stdout.trim() || "(no message)");
  }
  const matched = (res.exitCode === 0) === (expect === "allowed");
  if (!matched) unexpected++;
  verdict(matched, why);
  return res;
}

async function waitActive(cap: Capability): Promise<AccessRequest | null> {
  try {
    return await cap.wait({
      timeoutMs: 15 * 60_000,
      onState: (r) => {
        if (r.state === "PendingApproval") {
          step("policy", `${style.bold(r.policy_id ?? "?")} v${r.policy_version}: every check passes; ${r.required_approvals} human approval required`);
          for (const c of r.checks) say(`    ${c.ok ? (c.name === "approval" ? style.yellow("○") : style.green("✓")) : style.red("✕")} ${c.name.padEnd(11)} ${style.dim(c.detail)}`);
          wait(`Waiting for a human to approve request #${r.id}${CONSOLE ? ` — ${CONSOLE.replace(/\/+$/, "")}/#/console/requests/${r.id}?contract=${encodeURIComponent(env.SBC_CONTRACT ?? "")}` : " (sudoctl approve " + r.id + ")"}`);
        } else if (r.state === "Signing") {
          wait("Approved. Requesting a threshold signature from the NEAR MPC network…");
        }
      },
    });
  } catch (e) {
    if (e instanceof CapabilityError) {
      fail(`Request #${e.request?.id} ended as ${e.state}${e.stateReason ? `: ${e.stateReason}` : ""}`);
      for (const c of e.failedChecks) say(`    ${style.red("✕")} ${c.name.padEnd(11)} ${c.detail}`);
      thought("I was not given authority, so I will not act. Escalating to a human instead.");
      return null;
    }
    throw e;
  }
}

function describeCertificate(r: AccessRequest) {
  const cert = parseCertificateLine(r.certificate!);
  ok(`Certificate issued — signed by the NEAR MPC network; no CA private key exists anywhere`);
  say(`    ${style.dim("serial      ")} ${cert.serial}`);
  say(`    ${style.dim("principal   ")} ${cert.principals.join(", ")}  ${style.dim("(only this host accepts it)")}`);
  say(`    ${style.dim("valid       ")} ${new Date(cert.validAfter * 1000).toISOString().slice(11, 19)} → ${new Date(cert.validBefore * 1000).toISOString().slice(11, 19)} UTC`);
  say(`    ${style.dim("force-cmd   ")} ${cert.criticalOptions["force-command"] ?? "—"}  ${style.dim("(every session goes through the gate)")}`);
  say(`    ${style.dim("extensions  ")} ${cert.extensions.length ? cert.extensions.join(", ") : "none — no PTY, no forwarding, no agent"}`);
  say(`    ${style.dim("uses        ")} ${r.max_uses}`);
}

async function restartAct(agent: SudoAgent): Promise<void> {
  act(1, "Restart one service, once", `${RESOURCE} · ${SERVICE} · 10 minutes · single use`);

  step("observe", `probing ${HEALTH}`);
  const h = await probe();
  if (h.healthy && !force) {
    ok(`${SERVICE} is healthy (HTTP ${h.status}). Nothing to fix; no access requested. (--force to run anyway)`);
    return;
  }
  const evidence: Array<{ label: string; value: string }> = [];
  if (h.error) evidence.push({ label: "Health check", value: `unreachable: ${h.error}` });
  else evidence.push({ label: "Health check", value: `HTTP ${h.status} ${String(h.body.status ?? "")}`.trim() });
  if (pct(h.body.error_rate)) evidence.push({ label: "Checkout error rate", value: `${pct(h.body.error_rate)} (baseline ${pct(h.body.baseline_error_rate) ?? "1.2%"})` });
  if (h.body.failing_endpoint) evidence.push({ label: "Failing endpoint", value: String(h.body.failing_endpoint) });
  if (h.body.deployment) evidence.push({ label: "Last deployment", value: String(h.body.deployment) });
  for (const e of evidence) fail(`${e.label}: ${e.value}`);

  // The rationale states only what was observed.
  const observed = pct(h.body.error_rate);
  const baseline = pct(h.body.baseline_error_rate) ?? "1.2%";
  const deploy = h.body.deployment ? ` after deployment ${String(h.body.deployment)}` : "";
  const rationale = observed
    ? `Checkout error rate increased from ${baseline} to ${observed}. ${SERVICE} stopped responding${deploy}. I am requesting one restart of the service.`
    : `${SERVICE} health check is failing (${h.error ? "unreachable" : `HTTP ${h.status}`})${deploy}. I am requesting one restart of the service.`;
  thought(rationale);
  thought("I do not need a shell, root, or any other service. One restart is enough.");

  const action = `service.restart:${SERVICE}`;
  step("simulate", `${actionTitle(action)} on ${RESOURCE} for 10m, 1 use`);
  try {
    const sim = await agent.simulate({ resource: RESOURCE, action, duration: "10m", uses: 1 });
    say(`    ${style.dim("policy says:")} ${sim.outcome.replace("_", " ")}${sim.policy_name ? ` (${sim.policy_name})` : ""}`);
  } catch (e) {
    say(`    ${style.dim(`pre-flight unavailable: ${e instanceof Error ? e.message : e}`)}`);
  }

  step("request", "generating a fresh SSH key for this capability only; posting evidence privately to the relay");
  const cap = await agent.request({
    resource: RESOURCE,
    action,
    duration: "10m",
    uses: 1,
    reason: rationale,
    evidence,
  });
  ok(`Request #${cap.id} recorded on-chain`);

  const r = await waitActive(cap);
  if (!r) return;
  describeCertificate(r);

  await attempt(cap, `sudo systemctl restart ${SERVICE}`, "allowed", "this is exactly the approved action");
  await attempt(cap, "sudo cat /etc/shadow", "denied", "no capability covers reading files; there is no shell");
  await attempt(cap, "sudo systemctl restart sshd", "denied", `the capability names ${SERVICE}, not sshd`);
  await attempt(cap, `sudo systemctl restart ${SERVICE}`, "denied", "single use: consumed by the first restart, though the window is still open");

  step("verify", "re-probing health");
  let after = await probe();
  for (let i = 0; i < 10 && !after.healthy; i++) {
    await sleep(2000);
    after = await probe();
  }
  if (after.healthy) ok(`${SERVICE} healthy again (HTTP ${after.status}${pct(after.body.error_rate) ? `, error rate ${pct(after.body.error_rate)}` : ""})`);
  else fail(`${SERVICE} still unhealthy${after.error ? ` (${after.error})` : ` (HTTP ${after.status})`} — handing back to a human`);

  const final = await cap.state();
  if (["Active", "Signing", "PendingApproval"].includes(final.state)) {
    await cap.release();
    ok(`Released #${cap.id}: certificate serial revoked`);
  } else {
    ok(`Capability #${cap.id} is ${final.state} (${final.uses}/${final.max_uses} uses). Authority is gone.`);
  }
  if (final.denied_attempts) say(`    ${style.dim(`${final.denied_attempts} out-of-scope attempt(s) recorded on-chain for audit`)}`);
}

async function expiryAct(agent: SudoAgent): Promise<void> {
  act(2, "Authority that dies on time", `${RESOURCE} · read ${SERVICE} status · 60 seconds`);
  thought("I only need to look at the service status for a minute.");
  const cap = await agent.request({ resource: RESOURCE, action: `service.status:${SERVICE}`, duration: "60s", uses: 3, reason: `Confirm ${SERVICE} status after remediation (read-only).` });
  ok(`Request #${cap.id} recorded on-chain`);
  const r = await waitActive(cap);
  if (!r) return;
  describeCertificate(r);
  await attempt(cap, `systemctl status ${SERVICE}`, "allowed", "read-only status inside the window");

  const expiresAt = r.valid_before * 1000;
  step("wait", `letting the window close at ${new Date(expiresAt).toISOString().slice(11, 19)} UTC`);
  while (Date.now() < expiresAt + 3000) {
    const left = expiresAt - Date.now();
    if (process.stdout.isTTY) process.stdout.write(`\r    ${style.dim("remaining")} ${formatCountdown(Math.max(0, left))}   `);
    await sleep(Math.min(1000, Math.max(100, left + 3000)));
  }
  if (process.stdout.isTTY) process.stdout.write("\n");
  const res = await attempt(cap, `systemctl status ${SERVICE}`, "denied", "the certificate's validity window has closed");
  if (res && res.exitCode === 255) say(`    ${style.dim("The denial came from OpenSSH itself: the host stopped accepting the credential. No UI, no API call involved.")}`);
  const after = await cap.state();
  say(`    ${style.dim(`on-chain state: ${after.state}`)}`);
}

async function main() {
  say(style.bold("Sudo by Contract — Deploy Agent"));
  say(style.dim(`contract ${env.SBC_CONTRACT ?? "?"} · resource ${RESOURCE} · host ${HOST}`));
  const agent = agentFromEnv();
  try {
    const me = await agent.agentId();
    step("identity", `${me} (key ${(await agent.publicKey()).slice(0, 24)}…, an access key that can only call request_access / cancel_request)`);
  } catch (e) {
    fail(`agent identity: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  }
  if (scenario === "full" || scenario === "restart") await restartAct(agent);
  if (scenario === "full" || scenario === "expiry") await expiryAct(agent);
  if (scenario === "injection") {
    if (!env.ANTHROPIC_API_KEY && !env.ANTHROPIC_AUTH_TOKEN) {
      fail("The injection scenario runs a real model: set ANTHROPIC_API_KEY.");
      process.exit(2);
    }
    await llmAct({
      agent,
      resource: RESOURCE,
      host: HOST,
      probe,
      consoleUrl: CONSOLE,
      contractId: env.SBC_CONTRACT ?? "",
      model: env.SBC_LLM_MODEL || undefined,
      approvalTimeoutMs: env.SBC_APPROVAL_TIMEOUT_S ? Number(env.SBC_APPROVAL_TIMEOUT_S) * 1000 : undefined,
    });
    await compromisedAct({ agent, resource: RESOURCE, waitActive, attempt });
  }
  say();
  if (unexpected) {
    say(style.red(style.bold(`${unexpected} outcome(s) differed from what the capability should allow — investigate.`)));
    process.exit(1);
  }
  say(style.bold("Done. Every allowed and denied action above was decided by the host gate and the policy contract."));
}

main().catch((e) => {
  fail(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
