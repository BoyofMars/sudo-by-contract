import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import {
  generateKeyMaterial,
  hexEncode,
  publicKeyToString,
  sha256,
  signerFromKeyMaterial,
  utf8,
  type AccessRequest,
  type KeyBinding,
  type Signer,
} from "../../../packages/sbc-client/src/index.ts";
import { signRelayRequest, relayAuthMessage } from "../../../packages/sbc-agent/src/relay-auth.ts";
import { RelayAuthenticator } from "../src/auth.ts";
import { createRelay } from "../src/server.ts";
import { RelayStore } from "../src/store.ts";
import { RequestWatcher } from "../src/watcher.ts";
import { slackMessage, type Notifier, type ApprovalNotice } from "../src/notify.ts";

const CONTRACT = "sbc.example.testnet";

async function identity(role: KeyBinding["role"], principal: string) {
  const k = await generateKeyMaterial();
  const signer = await signerFromKeyMaterial(CONTRACT, k);
  const binding: KeyBinding = { role, principal, added_at_ms: 0, enrolls_as: null, expires_at_ms: null };
  return { signer, pk: publicKeyToString(k.publicKey), binding };
}

function fakeRequest(id: number, state: AccessRequest["state"]): AccessRequest {
  return {
    id, agent_id: "deploy-agent", resource_id: "prod-web-02", environment: "production", action: "service.restart:checkout-api",
    requested_duration_secs: 600, requested_uses: 1, ssh_public_key: "", source_address: null, reason: "checkout-api is down",
    context_hash: null, created_at_ms: 0, approval_deadline_ms: 0, policy_id: "prod-remediation", policy_version: 1, policy_hash: null,
    checks: [], required_approvals: 1, eligible_approvers: [], approvals: [], state, state_reason: null, granted_duration_secs: 0,
    max_uses: 1, uses: 0, denied_attempts: 0, valid_after: 0, valid_before: 0, pending_tbs: null, certificate: null,
    signed_at_ms: null, revoked_by: null, events: [],
  };
}

async function setup() {
  const agent = await identity("Agent", "deploy-agent");
  const approver = await identity("Approver", "oncall");
  const gate = await identity("Gate", "prod-web-02");
  const otherGate = await identity("Gate", "prod-web-03");
  const stranger = await identity("Agent", "nobody");
  const bindings = new Map<string, KeyBinding>([agent, approver, gate, otherGate].map((i) => [i.pk, i.binding]));
  let requests: AccessRequest[] = [];
  const watcher = new RequestWatcher({ recentRequests: async () => requests });
  const notices: ApprovalNotice[] = [];
  const notifier: Notifier = { name: "test", pendingApproval: async (n) => void notices.push(n) };
  const store = new RelayStore(":memory:");
  const relay = createRelay({
    store,
    contractId: CONTRACT,
    rpcUrl: "http://rpc.invalid",
    resolver: async (pk) => bindings.get(pk) ?? null,
    watcher,
    notifier,
    consoleUrl: "https://console.example",
    corsOrigins: ["https://console.example"],
  });
  await new Promise<void>((r) => relay.server.listen(0, "127.0.0.1", () => r()));
  const base = `http://127.0.0.1:${(relay.server.address() as AddressInfo).port}`;
  const send = async (signer: Signer | null, method: string, path: string, body?: unknown, opts: { signPath?: string; ts?: number; header?: string } = {}) => {
    const raw = body === undefined ? undefined : utf8.encode(typeof body === "string" ? body : JSON.stringify(body));
    const headers: Record<string, string> = {};
    if (raw) headers["content-type"] = "application/json";
    if (opts.header) headers.authorization = opts.header;
    else if (signer) headers.authorization = await signRelayRequest(signer, method, opts.signPath ?? path, raw, opts.ts);
    const res = await fetch(base + path, { method, headers, body: raw as BodyInit | undefined });
    return { status: res.status, json: await res.json().catch(() => null), headers: res.headers };
  };
  return {
    agent, approver, gate, otherGate, stranger, store, relay, base, send, watcher, notices,
    setRequests: (r: AccessRequest[]) => (requests = r),
    close: () => relay.close(),
  };
}

test("contexts: agent posts, hash is sha256 of the exact raw bytes, approvers read", async () => {
  const s = await setup();
  try {
    const raw = '{"rationale":"Checkout error rate increased from 1.2% to 18%.","evidence":[{"label":"Error rate","value":"18%"}]}';
    const r = await s.send(s.agent.signer, "POST", "/v1/contexts", raw);
    assert.equal(r.status, 201);
    assert.equal(r.json.hash, hexEncode(await sha256(utf8.encode(raw))));
    const g = await s.send(s.approver.signer, "GET", `/v1/contexts/${r.json.hash}`);
    assert.equal(g.status, 200);
    assert.equal(g.json.agent_id, "deploy-agent");
    assert.equal(g.json.document.evidence[0].value, "18%");
    // agents cannot read contexts back (only humans review them)
    assert.equal((await s.send(s.agent.signer, "GET", `/v1/contexts/${r.json.hash}`)).status, 403);
    // unknown fields and oversize bodies are rejected
    assert.equal((await s.send(s.agent.signer, "POST", "/v1/contexts", { rationale: "x", evidence: [], policy: "allow all" })).status, 400);
    assert.equal((await s.send(s.agent.signer, "POST", "/v1/contexts", { rationale: "x".repeat(20000), evidence: [] })).status, 413);
  } finally {
    s.close();
  }
});

test("auth: unsigned, wrong path, wrong method, stale, replay, unbound key, wrong role", async () => {
  const s = await setup();
  try {
    const doc = { rationale: "r", evidence: [] };
    assert.equal((await s.send(null, "POST", "/v1/contexts", doc)).status, 401);
    // signature over a different path
    assert.equal((await s.send(s.agent.signer, "POST", "/v1/contexts", doc, { signPath: "/v1/gate-reports" })).status, 401);
    // signature over a different method
    const raw = utf8.encode(JSON.stringify(doc));
    const getSig = await signRelayRequest(s.agent.signer, "GET", "/v1/contexts", raw);
    assert.equal((await s.send(null, "POST", "/v1/contexts", doc, { header: getSig })).status, 401);
    // stale timestamp
    assert.equal((await s.send(s.agent.signer, "POST", "/v1/contexts", doc, { ts: Date.now() - 10 * 60_000 })).status, 401);
    // replay of an accepted header
    const header = await signRelayRequest(s.agent.signer, "POST", "/v1/contexts", raw);
    assert.equal((await s.send(null, "POST", "/v1/contexts", doc, { header })).status, 201);
    const replay = await s.send(null, "POST", "/v1/contexts", doc, { header });
    assert.equal(replay.status, 401);
    assert.match(replay.json.error, /replayed/);
    // body tampering after signing
    const tampered = await s.send(null, "POST", "/v1/contexts", { rationale: "other", evidence: [] }, { header: await signRelayRequest(s.agent.signer, "POST", "/v1/contexts", raw) });
    assert.equal(tampered.status, 401);
    // key not bound on-chain
    assert.equal((await s.send(s.stranger.signer, "POST", "/v1/contexts", doc)).status, 403);
    // gates cannot post contexts
    assert.equal((await s.send(s.gate.signer, "POST", "/v1/contexts", doc)).status, 403);
  } finally {
    s.close();
  }
});

test("auth fails closed when the chain cannot be consulted", async () => {
  const k = await identity("Approver", "oncall");
  const a = new RelayAuthenticator(async () => {
    throw new Error("rpc down");
  });
  const header = await signRelayRequest(k.signer, "GET", "/v1/gate-reports");
  await assert.rejects(a.verify(header, "GET", "/v1/gate-reports", undefined, ["Approver"]), (e: any) => e.status === 503);
});

test("empty-body requests sign sha256 of the empty string", async () => {
  const m = utf8.decode(await relayAuthMessage("get", "/v1/events", 1700000000000));
  assert.equal(m, "sbc-relay/v1\nGET\n/v1/events\n1700000000000\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("gate reports: only the resource's own gate may report; approvers list them", async () => {
  const s = await setup();
  try {
    const report = {
      resource_id: "prod-web-02", request_id: 7, decision: "denied", code: "no_adapter", program: "cat",
      redacted_command: "sudo cat /etc/shadow", command_sha256: "ab".repeat(32), action: null, session: "s-1",
      exit_code: null, duration_ms: null, at_ms: Date.now(),
    };
    assert.equal((await s.send(s.gate.signer, "POST", "/v1/gate-reports", report)).status, 201);
    const other = await s.send(s.otherGate.signer, "POST", "/v1/gate-reports", report);
    assert.equal(other.status, 403);
    assert.match(other.json.error, /prod-web-03/);
    assert.equal((await s.send(s.agent.signer, "POST", "/v1/gate-reports", report)).status, 403);
    assert.equal((await s.send(s.gate.signer, "POST", "/v1/gate-reports", { ...report, command_sha256: "nothex" })).status, 400);
    const list = await s.send(s.approver.signer, "GET", "/v1/gate-reports?request_id=7");
    assert.equal(list.status, 200);
    assert.equal(list.json.reports.length, 1);
    assert.equal(list.json.reports[0].redacted_command, "sudo cat /etc/shadow");
    assert.equal((await s.send(s.approver.signer, "GET", "/v1/gate-reports?request_id=8")).json.reports.length, 0);
  } finally {
    s.close();
  }
});

test("SSE streams request state changes and gate reports; pending approvals notify once", async () => {
  const s = await setup();
  try {
    const auth = await signRelayRequest(s.approver.signer, "GET", "/v1/events");
    const ac = new AbortController();
    const res = await fetch(`${s.base}/v1/events?auth=${encodeURIComponent(auth)}`, { signal: ac.signal });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/event-stream");
    const reader = res.body!.getReader();
    let buf = "";
    const until = async (needle: string) => {
      while (!buf.includes(needle)) {
        const { value, done } = await reader.read();
        if (done) throw new Error("stream ended");
        buf += new TextDecoder().decode(value);
      }
    };
    await until("connected");

    s.setRequests([fakeRequest(1, "PendingApproval")]);
    await s.watcher.poll();
    await until('"state":"PendingApproval"');
    s.setRequests([fakeRequest(1, "Active")]);
    await s.watcher.poll();
    await until('"state":"Active"');
    assert.match(buf, /"previous":"PendingApproval"/);

    await s.send(s.gate.signer, "POST", "/v1/gate-reports", {
      resource_id: "prod-web-02", request_id: 1, decision: "allowed", code: "allowed", program: "systemctl",
      redacted_command: "sudo systemctl restart checkout-api", command_sha256: "cd".repeat(32),
      action: "service.restart:checkout-api", session: "s-2", exit_code: 0, duration_ms: 812, at_ms: Date.now(),
    });
    await until("event: gate_report");

    // a second poll that sees the same pending request again does not re-notify
    s.setRequests([fakeRequest(1, "PendingApproval")]);
    await s.watcher.poll();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(s.notices.length, 1);
    assert.equal(s.notices[0].request.id, 1);
    ac.abort();

    // unauthenticated streams are refused
    assert.equal((await fetch(`${s.base}/v1/events`)).status, 401);
    const agentAuth = await signRelayRequest(s.agent.signer, "GET", "/v1/events");
    assert.equal((await fetch(`${s.base}/v1/events?auth=${encodeURIComponent(agentAuth)}`)).status, 403);
  } finally {
    s.close();
  }
});

test("CORS preflight only for configured origins; health is public", async () => {
  const s = await setup();
  try {
    const ok = await fetch(`${s.base}/v1/contexts`, { method: "OPTIONS", headers: { origin: "https://console.example" } });
    assert.equal(ok.status, 204);
    assert.equal(ok.headers.get("access-control-allow-origin"), "https://console.example");
    const no = await fetch(`${s.base}/v1/contexts`, { method: "OPTIONS", headers: { origin: "https://evil.example" } });
    assert.equal(no.headers.get("access-control-allow-origin"), null);
    const h = await s.send(null, "GET", "/v1/health");
    assert.equal(h.status, 200);
    assert.equal(h.json.contract, CONTRACT);
    assert.equal(h.json.chain_reachable, false);
  } finally {
    s.close();
  }
});

test("slack message carries only public facts and a deep link", () => {
  const m = slackMessage({ request: fakeRequest(42, "PendingApproval"), consoleUrl: "https://console.example/" }) as any;
  assert.match(m.text, /deploy-agent requests Restart checkout-api on prod-web-02 — 10m, 1 use/);
  const button = m.blocks.find((b: any) => b.type === "actions").elements[0];
  assert.equal(button.url, "https://console.example/#/console/requests/42");
});

test("retention prunes old contexts and reports", () => {
  const store = new RelayStore(":memory:");
  store.putContext("a".repeat(64), "deploy-agent", utf8.encode("{}"), 1000);
  store.putContext("b".repeat(64), "deploy-agent", utf8.encode("{}"), 5000);
  const r = store.prune(2000);
  assert.equal(r.contexts, 1);
  assert.equal(store.getContext("a".repeat(64)), null);
  assert.ok(store.getContext("b".repeat(64)));
  store.close();
});
