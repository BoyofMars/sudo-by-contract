#!/usr/bin/env node
// sudoctl — request, approve and audit ephemeral machine authority.

import { ExecutionError, RpcError } from "../../../packages/sbc-client/src/index.ts";
import { CapabilityError, TimeoutError } from "../../../packages/sbc-agent/src/index.ts";
import { parseArgs, resolveCommand, UsageError } from "./args.ts";
import { ADMIN_HELP, commands, type Ctx } from "./commands.ts";
import { c } from "./ui.ts";

const GROUPS: Array<[string, string[]]> = [
  ["Setup", ["init", "enroll", "whoami"]],
  ["Agents", ["request", "wait", "status", "exec", "release", "simulate"]],
  ["Approvers", ["approvals", "approve", "deny", "revoke", "active", "audit"]],
  ["Inventory", ["resources", "agents", "policies", "ca"]],
  ["Admin", Object.keys(commands).filter((k) => k.startsWith("admin "))],
];

function help(out: (s: string) => void) {
  out(`${c.bold("sudoctl")} — give agents permission, not credentials.\n`);
  out(`Every capability is one action, on one resource, for a bounded time, approved by policy`);
  out(`(and humans when policy says so), signed by the NEAR MPC network, enforced on the host.\n`);
  for (const [title, names] of GROUPS) {
    out(c.dim(title.toUpperCase()));
    for (const n of names) out(`  ${n.padEnd(24)} ${commands[n].summary}`);
    out("");
  }
  out(`Global flags: --contract <id> --rpc <url> --relay <url> --as <principal> --json`);
  out(`Run \`sudoctl <command> --help\` for usage. Exit codes: 0 ok, 1 error, 2 usage, 3 refused, 4 timeout.`);
}

export async function main(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const out = (s = "") => process.stdout.write(s + "\n");
  const err = (s = "") => process.stderr.write(s + "\n");
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    err(`${c.red("usage:")} ${(e as Error).message}`);
    return 2;
  }
  const { command, args: positionals } = resolveCommand(args.positionals, Object.keys(commands));
  if (!command) {
    if (args.positionals[0] === "admin") {
      out(ADMIN_HELP + "\n");
      for (const n of Object.keys(commands).filter((k) => k.startsWith("admin "))) out(`  ${commands[n].usage}`);
      return args.positionals.length > 1 ? 2 : 0;
    }
    help(out);
    return args.positionals.length ? 2 : 0;
  }
  const cmd = commands[command];
  if (args.bool("help")) {
    out(`${cmd.summary}\n\n  ${cmd.usage}`);
    if (command.startsWith("admin")) out("\n" + ADMIN_HELP);
    return 0;
  }
  args.positionals = positionals;
  const ctx: Ctx = { args, env, out, err };
  try {
    return await cmd.run(ctx);
  } catch (e) {
    if (e instanceof UsageError) {
      err(`${c.red("usage:")} ${e.message}\n  ${cmd.usage}`);
      return 2;
    }
    if (e instanceof ExecutionError) {
      err(`${c.red("✕ contract refused:")} ${e.message}${e.txHash ? c.dim(`  (tx ${e.txHash})`) : ""}`);
      return 3;
    }
    if (e instanceof CapabilityError) {
      err(`${c.red("✕")} ${e.message}`);
      return 3;
    }
    if (e instanceof TimeoutError) {
      err(`${c.yellow("○")} ${e.message}`);
      return 4;
    }
    if (e instanceof RpcError) {
      err(`${c.red("✕ NEAR RPC:")} ${e.message}`);
      return 1;
    }
    err(`${c.red("✕")} ${e instanceof Error ? e.message : String(e)}`);
    if (env.SBC_DEBUG && e instanceof Error) err(e.stack ?? "");
    return 1;
  }
}

if (import.meta.main) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
