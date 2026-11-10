// ~/.sbc: config.json, keys/<role>-<principal>.json (NEAR CLI JSON format),
// sessions/<request id>/ (ephemeral SSH keys + certificates, via the SDK).

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DEFAULT_TESTNET_RPC, type Role } from "../../../packages/sbc-client/src/index.ts";
import { ensureDir, writePrivateFile } from "../../../packages/sbc-agent/src/files.ts";
import { UsageError } from "./args.ts";

export interface Config {
  contract?: string;
  rpc?: string;
  relay?: string;
  console?: string;
  /** resource id → "user@host:port" */
  hosts?: Record<string, string>;
}

export interface KeyFile {
  account_id: string;
  public_key: string;
  private_key: string;
  role: Role;
  principal: string;
  created_at_ms: number;
}

export function sbcHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.SBC_HOME ?? join(homedir(), ".sbc");
}

export function loadConfig(home = sbcHome()): Config {
  const p = join(home, "config.json");
  return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as Config) : {};
}

export function saveConfig(c: Config, home = sbcHome()): void {
  ensureDir(home);
  writeFileSync(join(home, "config.json"), JSON.stringify(c, null, 2) + "\n");
}

export interface Resolved {
  contract: string;
  rpc: string;
  relay?: string;
  console?: string;
  hosts: Record<string, string>;
}

/** Flags > environment > config file. */
export function resolveConfig(c: Config, env: NodeJS.ProcessEnv, overrides: { contract?: string; rpc?: string; relay?: string }): Resolved {
  const contract = overrides.contract ?? env.SBC_CONTRACT ?? c.contract;
  if (!contract) throw new UsageError("no contract configured — run `sudoctl init --contract <account>` or set SBC_CONTRACT");
  return {
    contract,
    rpc: overrides.rpc ?? env.SBC_RPC ?? c.rpc ?? DEFAULT_TESTNET_RPC,
    relay: overrides.relay ?? env.SBC_RELAY ?? c.relay,
    console: env.SBC_CONSOLE_URL ?? c.console,
    hosts: c.hosts ?? {},
  };
}

export function keysDir(home = sbcHome()): string {
  return join(home, "keys");
}

export function saveKey(k: KeyFile, home = sbcHome()): string {
  ensureDir(keysDir(home));
  const p = join(keysDir(home), `${k.role.toLowerCase()}-${k.principal}.json`);
  writePrivateFile(p, JSON.stringify(k, null, 2) + "\n");
  return p;
}

export function listKeys(home = sbcHome()): Array<KeyFile & { path: string }> {
  const d = keysDir(home);
  if (!existsSync(d)) return [];
  return readdirSync(d)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ ...(JSON.parse(readFileSync(join(d, f), "utf8")) as KeyFile), path: join(d, f) }));
}

/** Pick a key for one of `roles` (in preference order), optionally by principal (`--as`). */
export function findKey(roles: Role[], contract: string, principal?: string, home = sbcHome()): KeyFile {
  const keys = listKeys(home).filter((k) => k.account_id === contract);
  for (const role of roles) {
    const hit = keys.find((k) => k.role === role && (!principal || k.principal === principal));
    if (hit) return hit;
  }
  const want = roles.join(" or ");
  throw new UsageError(`no ${want} key for ${contract}${principal ? ` (principal ${principal})` : ""} in ${keysDir(home)} — enroll one with \`sudoctl enroll --token …\``);
}
