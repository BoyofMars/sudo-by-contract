import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs, resolveCommand, UsageError } from "../src/args.ts";
import { commands } from "../src/commands.ts";
import { findKey, resolveConfig, saveKey } from "../src/config.ts";
import { main } from "../src/main.ts";

const names = Object.keys(commands);

test("request: verb, target, flags, repeated evidence", () => {
  const a = parseArgs(["request", "restart", "checkout-api", "--on", "prod-web-02", "--for=10m", "--uses", "1", "--reason", "checkout is down", "--evidence", "Error rate=18%", "--evidence", "Deploy=#1842", "--wait"]);
  const { command, args } = resolveCommand(a.positionals, names);
  assert.equal(command, "request");
  assert.deepEqual(args, ["restart", "checkout-api"]);
  assert.equal(a.flag("on"), "prod-web-02");
  assert.equal(a.flag("for"), "10m");
  assert.equal(a.int("uses"), 1);
  assert.deepEqual(a.all("evidence"), ["Error rate=18%", "Deploy=#1842"]);
  assert.equal(a.bool("wait"), true);
});

test("exec keeps everything after -- verbatim", () => {
  const a = parseArgs(["exec", "41", "--host", "sbc-agent@demo-server:22", "--", "sudo", "systemctl", "restart", "--now", "checkout-api"]);
  assert.deepEqual(a.positionals, ["exec", "41"]);
  assert.deepEqual(a.rest, ["sudo", "systemctl", "restart", "--now", "checkout-api"]);
  assert.equal(a.flag("host"), "sbc-agent@demo-server:22");
});

test("longest command path wins", () => {
  assert.equal(resolveCommand(["admin", "resource", "create", "prod-web-02"], names).command, "admin resource create");
  assert.deepEqual(resolveCommand(["admin", "resource", "create", "prod-web-02"], names).args, ["prod-web-02"]);
  assert.equal(resolveCommand(["admin", "env", "add", "production"], names).command, "admin env add");
  assert.equal(resolveCommand(["admin", "token"], names).command, "admin token");
  assert.equal(resolveCommand(["nope"], names).command, null);
});

test("usage errors", () => {
  assert.throws(() => parseArgs(["--on"]), UsageError);
  assert.throws(() => parseArgs(["--json=yes"]), UsageError);
  assert.throws(() => parseArgs(["status", "--limit", "x"]).int("limit"), UsageError);
  assert.equal(parseArgs(["-h"]).bool("help"), true);
});

test("config precedence: flags > env > file; missing contract is a usage error", () => {
  const r = resolveConfig({ contract: "file.testnet", rpc: "https://file" }, { SBC_CONTRACT: "env.testnet" }, { contract: "flag.testnet" });
  assert.equal(r.contract, "flag.testnet");
  assert.equal(r.rpc, "https://file");
  assert.equal(resolveConfig({ contract: "file.testnet" }, { SBC_CONTRACT: "env.testnet" }, {}).contract, "env.testnet");
  assert.throws(() => resolveConfig({}, {}, {}), UsageError);
});

test("keys are chosen by role and principal", () => {
  const home = mkdtempSync(join(tmpdir(), "sbc-cli-"));
  saveKey({ account_id: "c.testnet", public_key: "ed25519:a", private_key: "ed25519:x", role: "Approver", principal: "oncall", created_at_ms: 0 }, home);
  saveKey({ account_id: "c.testnet", public_key: "ed25519:b", private_key: "ed25519:y", role: "Admin", principal: "success", created_at_ms: 0 }, home);
  assert.equal(findKey(["Approver", "Admin"], "c.testnet", undefined, home).principal, "oncall");
  assert.equal(findKey(["Approver", "Admin"], "c.testnet", "success", home).role, "Admin");
  assert.throws(() => findKey(["Agent"], "c.testnet", undefined, home), /no Agent key/);
  assert.throws(() => findKey(["Admin"], "other.testnet", undefined, home), UsageError);
});

test("main: help exits 0, unknown command exits 2, missing config exits 2", async () => {
  const env = { SBC_HOME: mkdtempSync(join(tmpdir(), "sbc-cli-")) };
  const write = process.stdout.write.bind(process.stdout);
  const ewrite = process.stderr.write.bind(process.stderr);
  let captured = "";
  (process.stdout as any).write = (s: string) => ((captured += s), true);
  (process.stderr as any).write = (s: string) => ((captured += s), true);
  try {
    process.env.SBC_HOME = env.SBC_HOME;
    assert.equal(await main(["--help"], env), 0);
    assert.match(captured, /give agents permission, not credentials/);
    assert.equal(await main(["frobnicate"], env), 2);
    assert.equal(await main(["request", "restart", "checkout-api", "--on", "prod-web-02", "--for", "10m", "--reason", "x"], env), 2);
    assert.match(captured, /no contract configured/);
    assert.equal(await main(["admin"], env), 0);
    assert.match(captured, /OWNER account/);
  } finally {
    (process.stdout as any).write = write;
    (process.stderr as any).write = ewrite;
    delete process.env.SBC_HOME;
  }
});
