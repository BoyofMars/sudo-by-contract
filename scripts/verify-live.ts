// Verify the live deployment yourself. No keys, no accounts, no trust in us.
//
//   npm run verify:live                       # bagyard-sexton.testnet
//   node scripts/verify-live.ts --contract <id> [--rpc <url>]
//
// Every fact comes from NEAR RPC; the Ed25519 check runs locally. If OpenSSH's
// ssh-keygen is installed, the certificate is also handed to OpenSSH itself.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyDeployment, type ProofStep } from "../packages/sbc-client/src/index.ts";

const argv = process.argv.slice(2);
const opt = (n: string, d: string) => (argv.includes(`--${n}`) ? argv[argv.indexOf(`--${n}`) + 1] : d);
const contractId = opt("contract", "bagyard-sexton.testnet");
const rpcUrl = opt("rpc", "https://rpc.testnet.fastnear.com");

const tty = process.stdout.isTTY;
const c = (code: number, s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = (s: string) => c(32, s), red = (s: string) => c(31, s), dim = (s: string) => c(2, s), bold = (s: string) => c(1, s);

console.log(`\n${bold("Sudo by Contract — independent verification")}  ${dim(`${contractId} via ${rpcUrl}`)}\n`);

let printed = 0;
const print = (steps: ProofStep[]) => {
  for (; printed < steps.length; printed++) {
    const s = steps[printed];
    if (s.status === "pending" || s.status === "running") return;
    console.log(`${s.status === "pass" ? green("✓") : red("✕")} ${bold(s.title)}`);
    console.log(`  ${dim(s.claim)}`);
    if (s.detail) console.log(`  ${s.detail}`);
    for (const [k, v] of s.facts ?? []) console.log(`  ${dim(k.padEnd(18))} ${v}`);
    console.log();
  }
};

const report = await verifyDeployment({ contractId, rpcUrl, onStep: print });
print(report.steps);

if (report.certificate) {
  const dir = mkdtempSync(join(tmpdir(), "sbc-verify-"));
  const file = join(dir, "issued-cert.pub");
  writeFileSync(file, report.certificate.line + "\n");
  const r = spawnSync("ssh-keygen", ["-L", "-f", file], { encoding: "utf8" });
  if (r.error) {
    console.log(dim("(ssh-keygen not found: skipping the OpenSSH cross-check)"));
  } else if (r.status === 0) {
    console.log(`${green("✓")} ${bold("OpenSSH agrees")}  ${dim("ssh-keygen -L parsed the certificate and accepted its CA signature:")}`);
    for (const l of r.stdout.split("\n").filter((x) => /Signing CA|Serial|Valid|Principals|sbc-|force-command|Extensions/.test(x))) console.log(`  ${l.trim()}`);
    console.log();
  } else {
    console.log(`${red("✕")} ssh-keygen rejected the certificate: ${r.stderr.trim()}`);
    report.ok = false;
  }
}

console.log(report.ok ? green(bold("All checks passed.")) + dim(" The CA has no private key; only the contract can sign with it.") : red(bold("Verification failed.")));
process.exit(report.ok ? 0 : 1);
