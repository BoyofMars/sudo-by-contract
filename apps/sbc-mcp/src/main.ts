#!/usr/bin/env node
// sbc-mcp — MCP server (stdio, newline-delimited JSON-RPC 2.0) that lets an AI
// agent request and use Sudo by Contract capabilities. stdout carries protocol
// messages only; diagnostics go to stderr.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { SudoAgent } from "../../../packages/sbc-agent/src/index.ts";
import { createMcpServer } from "./server.ts";

const env = process.env;
const log = (m: string) => process.stderr.write(`[sbc-mcp] ${m}\n`);

function need(name: string): string {
  const v = env[name];
  if (!v) {
    log(`${name} is required`);
    process.exit(2);
  }
  return v;
}

const secret = env.SBC_AGENT_KEY ?? (env.SBC_AGENT_KEY_FILE ? JSON.parse(readFileSync(env.SBC_AGENT_KEY_FILE, "utf8")).private_key : undefined);
if (!secret) {
  log("set SBC_AGENT_KEY (ed25519:…) or SBC_AGENT_KEY_FILE (a key file written by `sudoctl enroll`)");
  process.exit(2);
}

const agent = new SudoAgent({
  contractId: need("SBC_CONTRACT"),
  rpcUrl: env.SBC_RPC,
  relayUrl: env.SBC_RELAY,
  agentSecretKey: secret,
  stateDir: env.SBC_STATE_DIR ?? join(env.SBC_HOME ?? join(homedir(), ".sbc"), "mcp"),
});

const server = createMcpServer({
  agent,
  hosts: env.SBC_HOSTS ? JSON.parse(env.SBC_HOSTS) : {},
  consoleUrl: env.SBC_CONSOLE_URL ?? null,
});

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", async (line) => {
  if (!line.trim()) return;
  let msg: unknown;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }) + "\n");
    return;
  }
  const res = await server.handle(msg);
  if (res) process.stdout.write(JSON.stringify(res) + "\n");
});
rl.on("close", () => process.exit(0));
log(`ready for ${env.SBC_CONTRACT}`);
