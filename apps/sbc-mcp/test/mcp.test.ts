import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyMaterial, secretKeyToString, type AccessRequest } from "../../../packages/sbc-client/src/index.ts";
import { createMcpServer, PROTOCOL_VERSION, TOOLS, type McpAgent } from "../src/server.ts";

function req(id: number, state: AccessRequest["state"], extra: Partial<AccessRequest> = {}): AccessRequest {
  return {
    id, agent_id: "deploy-agent", resource_id: "prod-web-02", environment: "production", action: "service.restart:checkout-api",
    requested_duration_secs: 600, requested_uses: 1, ssh_public_key: "", source_address: null, reason: "r", context_hash: null,
    created_at_ms: 0, approval_deadline_ms: 0, policy_id: "prod-remediation", policy_version: 1, policy_hash: null, checks: [],
    required_approvals: 1, eligible_approvers: [], approvals: [], state, state_reason: null, granted_duration_secs: 600, max_uses: 1,
    uses: 0, denied_attempts: 0, valid_after: 0, valid_before: Math.floor(Date.now() / 1000) + 600, pending_tbs: null,
    certificate: null, signed_at_ms: null, revoked_by: null, events: [], ...extra,
  };
}

function stub() {
  const execs: Array<{ command: string; target: string }> = [];
  const agent: McpAgent = {
    listResources: async () => [{ id: "prod-web-02", environment: "production", status: "Active", services: ["checkout-api"] } as any],
    simulate: async () => ({ outcome: "needs_approval", policy_id: "prod-remediation", policy_name: "Production remediation", required_approvals: 1, checks: [{ name: "duration", ok: true, detail: "requested 10m / allowed 15m" }] }),
    request: async () => ({ id: 7 }),
    capability: (id) => ({
      state: async () => req(id, "PendingApproval"),
      wait: async () => req(id, "Active"),
      exec: async (command, target) => {
        execs.push({ command, target });
        return command.includes("shadow")
          ? { exitCode: 126, stdout: "", stderr: "sbc-gate: DENIED — `cat` is not an action Sudo by Contract can authorise\n", durationMs: 900 }
          : { exitCode: 0, stdout: "restarted checkout-api\n", stderr: "", durationMs: 1200 };
      },
      release: async () => {},
    }),
    sessionMeta: () => ({ resource: "prod-web-02" }),
  };
  return { agent, execs };
}

const call = (id: number, name: string, args: unknown) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

test("initialize, tools/list, notifications, unknown methods", async () => {
  const s = createMcpServer({ agent: stub().agent, hosts: {} });
  const init: any = await s.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(init.result.protocolVersion, PROTOCOL_VERSION);
  assert.ok(init.result.capabilities.tools);
  assert.equal(await s.handle({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  const list: any = await s.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.deepEqual(list.result.tools.map((t: any) => t.name), TOOLS.map((t) => t.name));
  assert.match(list.result.tools.find((t: any) => t.name === "request_capability").description, /never receive a reusable credential/);
  const nope: any = await s.handle({ jsonrpc: "2.0", id: 3, method: "resources/list" });
  assert.equal(nope.error.code, -32601);
  const bad: any = await s.handle(call(4, "exec_shell", {}));
  assert.equal(bad.error.code, -32602);
});

test("request → wait → run: allowed and refused actions are reported faithfully", async () => {
  const { agent, execs } = stub();
  const s = createMcpServer({ agent, hosts: { "prod-web-02": "sbc-agent@demo-server:22" }, consoleUrl: "https://console.example" });
  const r: any = await s.handle(call(1, "request_capability", { resource: "prod-web-02", action: "service.restart:checkout-api", duration: "10m", reason: "checkout down" }));
  assert.equal(r.result.structuredContent.state, "PendingApproval");
  assert.equal(r.result.structuredContent.review_url, "https://console.example/#/console/requests/7");
  const w: any = await s.handle(call(2, "wait_for_capability", { id: 7, timeout_seconds: 30 }));
  assert.match(w.result.content[0].text, /ACTIVE/);
  const ok: any = await s.handle(call(3, "run_approved_action", { id: 7, command: "sudo systemctl restart checkout-api" }));
  assert.equal(ok.result.isError, undefined);
  assert.equal(ok.result.structuredContent.exit_code, 0);
  const no: any = await s.handle(call(4, "run_approved_action", { id: 7, command: "sudo cat /etc/shadow" }));
  assert.equal(no.result.isError, true);
  assert.match(no.result.content[0].text, /DENIED/);
  assert.deepEqual(execs.map((e) => e.target), ["sbc-agent@demo-server:22", "sbc-agent@demo-server:22"]);
});

test("tool errors come back as isError results, not protocol errors", async () => {
  const { agent } = stub();
  const s = createMcpServer({ agent: { ...agent, sessionMeta: () => null }, hosts: {} });
  const r: any = await s.handle(call(1, "run_approved_action", { id: 9, command: "id" }));
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /no SSH address/);
});

test("stdio framing: newline-delimited JSON-RPC over a real process", async () => {
  const k = await generateKeyMaterial();
  const main = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src", "main.ts");
  const child = spawn(process.execPath, [main], {
    env: { ...process.env, SBC_CONTRACT: "sbc.example.testnet", SBC_AGENT_KEY: secretKeyToString(k), SBC_STATE_DIR: mkdtempSync(join(tmpdir(), "sbc-mcp-")) },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const lines: any[] = [];
  let buf = "";
  child.stdout.setEncoding("utf8").on("data", (d: string) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      lines.push(JSON.parse(buf.slice(0, i)));
      buf = buf.slice(i + 1);
    }
  });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "t", version: "1" } } }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
  child.stdin.write("not json\n");
  const deadline = Date.now() + 10_000;
  while (lines.length < 3 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
  child.stdin.end();
  child.kill();
  // responses are concurrent (a long wait_for_capability must not block ping), so match by id
  const byId = (id: number | null) => lines.find((l) => l.id === id);
  assert.equal(lines.length, 3, "exactly one response per request; none for the notification");
  assert.equal(byId(1).result.serverInfo.name, "sudo-by-contract");
  assert.equal(byId(2).result.tools.length, TOOLS.length);
  assert.equal(byId(null).error.code, -32700);
});
