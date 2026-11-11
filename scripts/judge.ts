// One command for reviewers: run everything that can be checked from a clone
// and print each claim next to the evidence that backs it.
//
//   npm ci && npm run judge              # all checks (the last one reads NEAR testnet)
//   npm run judge -- --offline           # skip the live testnet check
//
// Needs Node >= 23.6 (runs TypeScript directly) and Rust (cargo). ssh-keygen
// is optional: when present, OpenSSH itself checks the live certificate too.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const offline = process.argv.includes("--offline");
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const [bold, dim, green, red, yellow] = [c("1"), c("2"), c("32"), c("31"), c("33")];

type Row = { claim: string; evidence: string; result: string; ok: boolean | null };
const tests = (n: number) => `${n} test${n === 1 ? "" : "s"}`;
const rows: Row[] = [];
let failed = false;

function run(cmd: string): { code: number; out: string; secs: number } {
  const t0 = Date.now();
  // one shell so stdout and stderr interleave in order (cargo prints test
  // binary names on stderr and results on stdout)
  const p = spawnSync(`${cmd} 2>&1`, { cwd: root, shell: true, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: p.status ?? 1, out: p.stdout ?? "", secs: Math.round((Date.now() - t0) / 1000) };
}

function have(cmd: string, arg = "--version"): boolean {
  return spawnSync(cmd, [arg], { shell: true, stdio: "ignore" }).status === 0;
}

function step(title: string) {
  console.log(`\n${bold("▸ " + title)}`);
}

// ------------------------------------------------------------ prerequisites
step("Prerequisites");
const [maj, min] = process.versions.node.split(".").map(Number);
const nodeOk = maj > 23 || (maj === 23 && min >= 6);
console.log(`  node ${process.versions.node} ${nodeOk ? green("✓") : red("✕ needs >= 23.6 (see .nvmrc)")}`);
const cargoOk = have("cargo");
console.log(`  cargo ${cargoOk ? green("✓") : red("✕ install Rust from https://rustup.rs")}`);
const sshOk = spawnSync("ssh-keygen", ["-?"], { stdio: "ignore" }).error === undefined;
console.log(`  ssh-keygen ${sshOk ? green("✓") : yellow("– optional, skipped")}`);
const depsOk = existsSync(join(root, "node_modules"));
console.log(`  node_modules ${depsOk ? green("✓") : red("✕ run `npm ci` first")}`);
if (!nodeOk || !cargoOk || !depsOk) {
  console.log(red("\nFix the prerequisites above and run again."));
  process.exit(2);
}

// ------------------------------------------------------------------- rust
step("Rust: contract, gate, OpenSSH encoding, WebAssembly build of the gate's parser");
console.log(dim("  cargo test --workspace   (the first run compiles near-sdk; allow a few minutes)"));
const cargo = run("cargo test --workspace");
const byBinary = new Map<string, { passed: number; failed: number }>();
let current = "?";
for (const line of cargo.out.split(/\r?\n/)) {
  const m = line.match(/Running .*?deps[\\/]([a-z_]+)-[0-9a-f]+/) ?? line.match(/Doc-tests ([a-z_]+)/);
  if (m) current = m[1];
  const r = line.match(/test result: \w+\. (\d+) passed; (\d+) failed/);
  if (r) {
    const prev = byBinary.get(current) ?? { passed: 0, failed: 0 };
    byBinary.set(current, { passed: prev.passed + Number(r[1]), failed: prev.failed + Number(r[2]) });
  }
}
const count = (...names: string[]) =>
  names.reduce((a, n) => ({ passed: a.passed + (byBinary.get(n)?.passed ?? 0), failed: a.failed + (byBinary.get(n)?.failed ?? 0) }), { passed: 0, failed: 0 });
const rustTotal = [...byBinary.values()].reduce((a, b) => ({ passed: a.passed + b.passed, failed: a.failed + b.failed }), { passed: 0, failed: 0 });
console.log(`  ${cargo.code === 0 ? green("✓") : red("✕")} ${rustTotal.passed} passed, ${rustTotal.failed} failed ${dim(`(${cargo.secs} s)`)}`);
if (cargo.code !== 0) {
  failed = true;
  console.log(cargo.out.split(/\r?\n/).filter((l) => /FAILED|panicked|error(\[|:)/.test(l)).slice(0, 15).map((l) => "    " + l).join("\n"));
}
const rustRow = (claim: string, evidence: string, ...bins: string[]) => {
  const n = count(...bins);
  const ok = cargo.code === 0 && n.failed === 0 && n.passed > 0;
  rows.push({ claim, evidence, result: `${tests(n.passed)} passed${n.failed ? `, ${n.failed} failed` : ""}`, ok });
};
rustRow("The contract enforces policy, approvals, single use, expiry, revocation and host binding; MPC signatures are verified before a certificate is issued", "contracts/sbc-policy/src/tests.rs (simulated MPC callback with real Ed25519 signatures)", "sbc_policy");
rustRow("The host gate turns commands into typed actions, checks the certificate itself, consumes a use on-chain before running anything, and fails closed", "crates/sbc-gate: unit tests + tests/exec_flow.rs + tests/enroll_key_file.rs (mock NEAR RPC that verifies every transaction signature)", "sbc_gate", "exec_flow", "enroll_key_file");
rustRow("Certificates are standard OpenSSH certificates; the command grammar is closed", "crates/sbc-core tests", "sbc_core");
rustRow("The in-browser playground runs the gate's real parser", "crates/sbc-wasm test", "sbc_wasm");

// --------------------------------------------------------------- typescript
step("TypeScript: SDK, CLI, relay, MCP server, NEAR transaction encoding");
const node = run("npm test");
const pass = Number(node.out.match(/ℹ pass (\d+)/)?.[1] ?? 0);
const fail = Number(node.out.match(/ℹ fail (\d+)/)?.[1] ?? 0);
const nodeTestsOk = node.code === 0 && fail === 0 && pass > 0;
console.log(`  ${nodeTestsOk ? green("✓") : red("✕")} ${pass} passed, ${fail} failed ${dim(`(${node.secs} s)`)}`);
if (!nodeTestsOk) failed = true;
rows.push({
  claim: "No wallet or NEAR SDK at runtime: hand-written borsh transactions match @near-js byte for byte; SDK, CLI, relay and MCP behave as documented",
  evidence: "packages/*/test, apps/*/test (npm test)",
  result: `${tests(pass)} passed${fail ? `, ${fail} failed` : ""}`,
  ok: nodeTestsOk,
});

// --------------------------------------------------------------------- live
if (offline) {
  rows.push({ claim: "The live deployment's CA key is derived by NEAR's MPC network and only the contract can use it", evidence: "npm run verify:live", result: "skipped (--offline)", ok: null });
} else {
  step("Live: the deployed contract and NEAR's MPC signer on testnet (no keys needed)");
  const live = run("node scripts/verify-live.ts");
  const openssh = /OpenSSH agrees/.test(live.out);
  const checks = (live.out.match(/^✓ /gm) ?? []).length - (openssh ? 1 : 0);
  const crosses = (live.out.match(/^✕ /gm) ?? []).length;
  console.log(`  ${live.code === 0 ? green("✓") : red("✕")} ${checks} checks passed${crosses ? `, ${crosses} failed` : ""}${openssh ? ", and ssh-keygen accepted the certificate" : ""} ${dim(`(${live.secs} s)`)}`);
  if (live.code !== 0) {
    failed = true;
    console.log(live.out.split(/\r?\n/).slice(-12).map((l) => "    " + l).join("\n"));
  }
  rows.push({
    claim: "The live deployment's SSH CA key is derived by NEAR's MPC network for the contract, only the contract can use it, and a certificate it issued verifies",
    evidence: "scripts/verify-live.ts against bagyard-sexton.testnet and v1.signer-prod.testnet",
    result: `${checks} checks passed${openssh ? " + ssh-keygen" : ""}`,
    ok: live.code === 0,
  });
}

rows.push({
  claim: "End to end with real OpenSSH: an agent gets a capability on testnet, the MPC network signs it, the gate runs the command, and sshd refuses the certificate after expiry",
  evidence: "github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml (every 8 hours; needs the repository's scoped keys, so it runs in CI, not from a clone)",
  result: "see the latest run",
  ok: null,
});

// ------------------------------------------------------------------ report
console.log(`\n${bold("Claims and evidence")}\n`);
for (const r of rows) {
  const mark = r.ok === true ? green("✓") : r.ok === false ? red("✕") : dim("–");
  console.log(`${mark} ${bold(r.claim)}`);
  console.log(`  ${dim("evidence")} ${r.evidence}`);
  console.log(`  ${dim("result  ")} ${r.ok === false ? red(r.result) : r.result}\n`);
}
console.log(failed ? red(bold("Some checks failed (details above).")) : green(bold("Everything that can run from a clone passed.")));
process.exit(failed ? 1 : 0);
