import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateKeyMaterial,
  publicKeyToString,
  secretKeyToString,
  type AccessRequest,
  type RequestAccessArgs,
} from "../../sbc-client/src/index.ts";
import { CapabilityError, SudoAgent, buildSshArgv, normalizeAction, parseDuration, parseSshTarget, type ContractLike } from "../src/index.ts";

function req(id: number, state: AccessRequest["state"], extra: Partial<AccessRequest> = {}): AccessRequest {
  return {
    id, agent_id: "deploy-agent", resource_id: "prod-web-02", environment: "production", action: "service.restart:checkout-api",
    requested_duration_secs: 600, requested_uses: 1, ssh_public_key: "", source_address: null, reason: "r", context_hash: null,
    created_at_ms: 0, approval_deadline_ms: 0, policy_id: "p", policy_version: 1, policy_hash: null, checks: [], required_approvals: 1,
    eligible_approvers: [], approvals: [], state, state_reason: null, granted_duration_secs: 600, max_uses: 1, uses: 0,
    denied_attempts: 0, valid_after: 0, valid_before: Math.floor(Date.now() / 1000) + 600, pending_tbs: null, certificate: null,
    signed_at_ms: null, revoked_by: null, events: [], ...extra,
  };
}

async function stubAgent(states: AccessRequest[]) {
  const calls: { requestAccess: RequestAccessArgs[]; cancel: number[]; contexts: unknown[] } = { requestAccess: [], cancel: [], contexts: [] };
  let i = 0;
  const k = await generateKeyMaterial();
  const contract = {
    async requestAccess(_s: unknown, a: RequestAccessArgs) {
      calls.requestAccess.push(a);
      return 41;
    },
    async request(id: number) {
      const r = states[Math.min(i++, states.length - 1)];
      return { ...r, id };
    },
    async requests() {
      return [];
    },
    async cancelRequest(_s: unknown, id: number) {
      calls.cancel.push(id);
    },
    async simulate() {
      return { outcome: "needs_approval", policy_id: "p", policy_name: "P", required_approvals: 1, checks: [] };
    },
    async whoami(pk: string) {
      return { public_key: pk, binding: { role: "Agent", principal: "deploy-agent", added_at_ms: 0, enrolls_as: null, expires_at_ms: null } };
    },
    async resources() {
      return [];
    },
    async resource() {
      return null;
    },
  } as unknown as ContractLike;
  const agent = new SudoAgent({
    contractId: "sbc.example.testnet",
    agentSecretKey: secretKeyToString(k),
    stateDir: mkdtempSync(join(tmpdir(), "sbc-agent-")),
    contract,
    relay: { postContext: async (doc) => (calls.contexts.push(doc), "ab".repeat(32)) },
    pollIntervalMs: 1,
  });
  return { agent, calls, publicKey: publicKeyToString(k.publicKey) };
}

test("durations", () => {
  assert.equal(parseDuration("90s"), 90);
  assert.equal(parseDuration("10m"), 600);
  assert.equal(parseDuration("1h30m"), 5400);
  assert.equal(parseDuration(" 2h "), 7200);
  assert.equal(parseDuration("600"), 600);
  assert.equal(parseDuration(60), 60);
  for (const bad of ["", "10x", "m", "-5m", "10m extra", "1.5h"]) assert.throws(() => parseDuration(bad), new RegExp("invalid duration"), bad);
});

test("actions are normalised and validated before anything is signed", () => {
  assert.equal(normalizeAction({ kind: "service.restart", target: "checkout-api" }), "service.restart:checkout-api");
  assert.equal(normalizeAction("logs.read:checkout-api"), "logs.read:checkout-api");
  assert.throws(() => normalizeAction("shell.exec:bash"), /unknown action kind/);
  assert.throws(() => normalizeAction("service.restart:--now"), /invalid target/);
  assert.throws(() => normalizeAction("service.restart:a;id"), /invalid target/);
});

test("ssh targets and argv: no shell, options end before the host", () => {
  assert.deepEqual(parseSshTarget("sbc-agent@demo-server:2222"), { user: "sbc-agent", host: "demo-server", port: 2222 });
  assert.deepEqual(parseSshTarget("10.0.0.5"), { user: "sbc-agent", host: "10.0.0.5", port: 22 });
  assert.throws(() => parseSshTarget("-oProxyCommand=id"));
  assert.throws(() => parseSshTarget("a@b:c"));
  const argv = buildSshArgv({
    keyPath: "/k/id_ed25519",
    certPath: "/k/id_ed25519-cert.pub",
    knownHostsPath: "/k/known_hosts",
    target: { user: "sbc-agent", host: "demo-server", port: 22 },
    command: "sudo systemctl restart checkout-api",
  });
  const dd = argv.indexOf("--");
  assert.ok(dd > 0);
  assert.deepEqual(argv.slice(dd), ["--", "demo-server", "sudo systemctl restart checkout-api"]);
  assert.ok(argv.includes("CertificateFile=/k/id_ed25519-cert.pub"));
  assert.ok(argv.includes("IdentitiesOnly=yes"));
  assert.ok(argv.includes("BatchMode=yes"));
  assert.throws(() => buildSshArgv({ keyPath: "k", certPath: "c", knownHostsPath: "h", target: { user: "u", host: "h", port: 22 }, command: "id\nrm -rf /" }));
});

test("request: ephemeral key on disk, private context hashed, only hash + short reason on-chain", async () => {
  const { agent, calls } = await stubAgent([req(41, "PendingApproval")]);
  const cap = await agent.request({
    resource: "prod-web-02",
    action: { kind: "service.restart", target: "checkout-api" },
    duration: "10m",
    reason: "x".repeat(400),
    evidence: [{ label: "Error rate", value: "18%" }],
  });
  assert.equal(cap.id, 41);
  const a = calls.requestAccess[0];
  assert.equal(a.duration_secs, 600);
  assert.equal(a.uses, 1);
  assert.equal(a.context_hash, "ab".repeat(32));
  assert.ok(a.reason.length <= 280);
  assert.equal(Buffer.from(a.ssh_public_key, "base64").length, 32);
  assert.match(readFileSync(cap.keyPath, "utf8"), /BEGIN OPENSSH PRIVATE KEY/);
  assert.ok(existsSync(join(cap.dir, "meta.json")));
  assert.deepEqual((calls.contexts[0] as any).evidence, [{ label: "Error rate", value: "18%" }]);
});

test("wait: reports transitions, writes the certificate when Active", async () => {
  const cert = "ssh-ed25519-cert-v01@openssh.com AAAA sbc-cap-41";
  const { agent } = await stubAgent([req(41, "PendingApproval"), req(41, "PendingApproval"), req(41, "Signing"), req(41, "Active", { certificate: cert })]);
  const cap = await agent.request({ resource: "prod-web-02", action: "service.restart:checkout-api", duration: 600, reason: "r" });
  const seen: string[] = [];
  const r = await cap.wait({ onState: (x) => seen.push(x.state) });
  assert.deepEqual(seen, ["PendingApproval", "Signing", "Active"]);
  assert.equal(r.state, "Active");
  assert.equal(readFileSync(cap.certPath, "utf8").trim(), cert);
  assert.ok(cap.remaining() > 500_000);
});

test("wait: terminal states throw with the failing policy checks", async () => {
  const { agent } = await stubAgent([
    req(41, "Rejected", {
      state_reason: "duration: requested 30m / allowed 15m",
      checks: [
        { name: "identity", ok: true, detail: "deploy-agent" },
        { name: "duration", ok: false, detail: "requested 30m / allowed 15m" },
      ],
    }),
  ]);
  const cap = await agent.request({ resource: "prod-web-02", action: "service.restart:checkout-api", duration: "30m", reason: "r" });
  await assert.rejects(cap.wait(), (e: unknown) => {
    assert.ok(e instanceof CapabilityError);
    assert.equal(e.state, "Rejected");
    assert.deepEqual(e.failedChecks.map((c) => c.name), ["duration"]);
    return true;
  });
});

test("release and reopen by id", async () => {
  const { agent, calls } = await stubAgent([req(41, "Active", { certificate: "ssh-ed25519-cert-v01@openssh.com AAAA" })]);
  const cap = await agent.request({ resource: "prod-web-02", action: "service.restart:checkout-api", duration: 600, reason: "r" });
  const again = agent.capability(41);
  assert.equal(again.keyPath, cap.keyPath);
  assert.equal(agent.sessionMeta(41)?.action, "service.restart:checkout-api");
  await again.release();
  assert.deepEqual(calls.cancel, [41]);
  assert.throws(() => agent.capability(999), /no local key/);
});
