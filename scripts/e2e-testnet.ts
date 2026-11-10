// Live end-to-end verification against NEAR testnet and the real MPC signer.
//
//   node scripts/e2e-testnet.ts --owner you.testnet --contract sbc.you.testnet [--gate-bin path/to/sbc-gate]
//
// Exercises every component except sshd itself (the Docker sandbox covers sshd):
//   policy contract · NEAR MPC threshold Ed25519 · OpenSSH ssh-keygen verification of the
//   MPC-signed certificate · the real sbc-gate binary (dry-run backend) calling consume() ·
//   KRL generation from on-chain revocations · expiry by block time.
//
// Owner-signed setup calls use your own `near` CLI keychain (this script never reads it).

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SudoContract,
  generateKeyMaterial,
  parseCertificateLine,
  publicKeyToString,
  secretKeyToString,
  signerFromKeyMaterial,
  sshPublicKeyLine,
  verify,
  b64decode,
  type AccessRequest,
} from "../packages/sbc-client/src/index.ts";

const argv = process.argv.slice(2);
const opt = (n: string, d?: string) => (argv.indexOf(`--${n}`) >= 0 ? argv[argv.indexOf(`--${n}`) + 1] : d);
const owner = opt("owner")!;
const contractId = opt("contract")!;
const rpcUrl = opt("rpc", "https://rpc.testnet.fastnear.com")!;
const exe = process.platform === "win32" ? ".exe" : "";
const gateBin = opt("gate-bin", join(process.env.CARGO_TARGET_DIR ?? "target", "debug", `sbc-gate${exe}`))!;
if (!owner || !contractId) {
  console.error("usage: node scripts/e2e-testnet.ts --owner <you>.testnet --contract <sbc>.<you>.testnet [--gate-bin path]");
  process.exit(2);
}

const c = new SudoContract(contractId, rpcUrl);
const dir = mkdtempSync(join(tmpdir(), "sbc-e2e-"));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const results: Array<{ step: string; ok: boolean; detail: string }> = [];
const t0 = Date.now();
function check(step: string, ok: boolean, detail = "") {
  results.push({ step, ok, detail });
  console.log(`${ok ? "✓" : "✕"} ${step}${detail ? ` — ${detail}` : ""}`);
  if (!ok) {
    summary();
    process.exit(1);
  }
}
function summary() {
  console.log(`\n${results.filter((r) => r.ok).length}/${results.length} checks passed in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
}
function ownerCall(method: string, args: object, tgas = 100) {
  execFileSync("near", ["contract", "call-function", "as-transaction", contractId, method, "json-args", JSON.stringify(args),
    "prepaid-gas", `${tgas}.0 Tgas`, "attached-deposit", "0 NEAR", "sign-as", owner,
    "network-config", "testnet", "sign-with-legacy-keychain", "send"], { stdio: ["ignore", "ignore", "inherit"] });
}
async function enrolled(role: "Agent" | "Approver" | "Gate", principal: string) {
  const token = await generateKeyMaterial();
  ownerCall("create_enrollment", { role, principal, token_public_key: publicKeyToString(token.publicKey), ttl_secs: 900 }, 50);
  return token;
}
async function until(id: number, pred: (r: AccessRequest) => boolean, timeoutMs = 120_000): Promise<AccessRequest> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const r = (await c.request(id))!;
    if (pred(r)) return r;
    if (Date.now() > end) throw new Error(`timeout waiting on request ${id} (state ${r.state})`);
    await sleep(1000);
  }
}

// ------------------------------------------------------------------ setup
const suffix = Math.random().toString(16).slice(2, 6);
const resourceId = `e2e-web-${suffix}`;
console.log(`Sudo by Contract live e2e — contract ${contractId}, resource ${resourceId}\n`);

const ov = await c.overview();
check("contract reachable and configured", ov.environments.some((e) => e.name === "production" && e.ca_public_key_ssh), `MPC ${ov.config.mpc_contract}, audit seq ${ov.audit_seq}`);
const caLine = (await c.ca("production"))!;

ownerCall("create_resource", { id: resourceId, label: resourceId, environment: "production", tags: ["e2e"], services: ["checkout-api", "sshd"] });
ownerCall("create_approver", { id: `e2e-approver-${suffix}`, label: "E2E approver", is_admin: false });

// gate: the real binary enrolls itself with a one-time token
const gateToken = await enrolled("Gate", resourceId);
const gateDir = join(dir, "gate");
const enroll = spawnSync(gateBin, ["enroll", "--contract", contractId, "--resource", resourceId, "--token", secretKeyToString(gateToken),
  "--rpc", rpcUrl, "--backend", "dryrun", "--config-dir", gateDir, "--ssh-dir", join(gateDir, "ssh")], { encoding: "utf8" });
check("sbc-gate enroll (one-time token → gate key on-chain)", enroll.status === 0, enroll.status === 0 ? "" : enroll.stderr);
const res = await c.resource(resourceId);
check("resource active with enrolled gate key", res?.status === "Active" && !!res.gate_key, res?.gate_key ?? "");

const agentToken = await enrolled("Agent", "deploy-agent");
const agentKey = await generateKeyMaterial();
await c.completeEnrollment(await signerFromKeyMaterial(contractId, agentToken), publicKeyToString(agentKey.publicKey));
const agent = await signerFromKeyMaterial(contractId, agentKey);
const apprToken = await enrolled("Approver", `e2e-approver-${suffix}`);
const apprKey = await generateKeyMaterial();
await c.completeEnrollment(await signerFromKeyMaterial(contractId, apprToken), publicKeyToString(apprKey.publicKey));
const approver = await signerFromKeyMaterial(contractId, apprKey);
check("agent and approver identities enrolled", (await c.whoami(publicKeyToString(agentKey.publicKey))).binding?.role === "Agent");

function gate(command: string, cert: string) {
  const authFile = join(dir, `auth-${Date.now()}`);
  writeFileSync(authFile, `publickey ${cert}\n`);
  return spawnSync(gateBin, [], {
    encoding: "utf8",
    env: { ...process.env, SBC_GATE_CONFIG: join(gateDir, "gate.toml"), SSH_ORIGINAL_COMMAND: command, SSH_USER_AUTH: authFile },
  });
}

// ------------------------------------------------- request → approve → issue
const ssh = await generateKeyMaterial();
let t = Date.now();
const id = await c.requestAccess(agent, {
  resource_id: resourceId,
  action: "service.restart:checkout-api",
  duration_secs: 600,
  ssh_public_key: sshPublicKeyLine(ssh.publicKey),
  reason: "e2e: checkout-api unhealthy after deploy; requesting one restart",
});
let r = (await c.request(id))!;
check("request evaluated by policy → awaiting approval", r.state === "PendingApproval" && r.checks.every((x) => x.ok), `policy ${r.policy_id} v${r.policy_version}, ${r.checks.length} checks ✓`);

t = Date.now();
await c.approve(approver, id);
r = await until(id, (x) => x.state !== "Signing" && x.state !== "PendingApproval");
check("approval → MPC threshold signature → certificate", r.state === "Active" && !!r.certificate, `${((Date.now() - t) / 1000).toFixed(1)} s from approval to Active`);

// ------------------------------------------------ OpenSSH verifies the MPC signature
const certFile = join(dir, "id_ed25519-cert.pub");
writeFileSync(certFile, r.certificate! + "\n");
const L = spawnSync("ssh-keygen", ["-L", "-f", certFile], { encoding: "utf8" });
check("ssh-keygen parses and verifies the MPC-signed certificate", L.status === 0 && /sbc-/.test(L.stdout) && /force-command/.test(L.stdout), L.stdout.split("\n").filter((l) => /Serial|Valid|Signing CA/.test(l)).map((l) => l.trim()).join(" | "));
const cert = parseCertificateLine(r.certificate!);
const blob = b64decode(r.certificate!.split(" ")[1]);
const caRaw = b64decode(caLine.split(" ")[1]).slice(-32);
const signedLen = blob.length - (4 + 4 + 11 + 4 + 64);
const sigOk = await verify(caRaw, blob.slice(0, signedLen), blob.slice(blob.length - 64));
check("certificate is signed by the environment CA the MPC network derived for this contract", sigOk && sshPublicKeyLine(cert.caPublicKey) === caLine.split(" ").slice(0, 2).join(" "));
check("certificate is bounded: one principal, force-command, no extensions, ~10 min",
  cert.principals.length === 1 && cert.principals[0] === `sbc-${resourceId}` && cert.criticalOptions["force-command"] === "/usr/local/sbin/sbc-gate" && cert.extensions.length === 0 && cert.validBefore - cert.validAfter === 660);

// ------------------------------------------------------- execution at the gate
let g = gate("sudo systemctl restart checkout-api", r.certificate!);
check("gate: approved restart executes (consume → allowed)", g.status === 0 && /systemctl","restart","checkout-api/.test(g.stdout), g.stderr.trim().split("\n").pop());
g = gate("sudo cat /etc/shadow", r.certificate!);
check("gate: `sudo cat /etc/shadow` denied (no adapter)", g.status === 126, g.stderr.trim().split("\n")[0]);
g = gate("sudo systemctl restart sshd", r.certificate!);
check("gate: `sudo systemctl restart sshd` denied (out of scope, decided on-chain)", g.status === 77 && /out_of_scope/.test(g.stderr), g.stderr.trim());
g = gate("sudo systemctl restart checkout-api", r.certificate!);
check("gate: second restart denied (single use consumed)", g.status === 77 && /exhausted/.test(g.stderr), g.stderr.trim());
r = (await c.request(id))!;
check("on-chain record: Exhausted, 1 use, denials counted", r.state === "Exhausted" && r.uses === 1 && r.denied_attempts >= 2, `events: ${r.events.map((e) => e.kind).join(" → ")}`);

// ------------------------------------------------------------- revocation
const ssh2 = await generateKeyMaterial();
const id2 = await c.requestAccess(agent, { resource_id: resourceId, action: "service.status:checkout-api", duration_secs: 300, uses: 3, ssh_public_key: sshPublicKeyLine(ssh2.publicKey), reason: "e2e: revocation check" });
const r2 = await until(id2, (x) => x.state === "Active" || x.state === "Failed" || x.state === "Rejected");
check("auto-approved read-only capability issued", r2.state === "Active", `policy ${r2.policy_id}`);
check("gate: status allowed before revocation", gate("systemctl status checkout-api", r2.certificate!).status === 0);
await c.revoke(approver, id2, "e2e revocation");
g = gate("systemctl status checkout-api", r2.certificate!);
check("gate: denied immediately after revoke (next command)", g.status === 77 && /revoked/.test(g.stderr), g.stderr.trim());
const sync = spawnSync(gateBin, ["sync"], { encoding: "utf8", env: { ...process.env, SBC_GATE_CONFIG: join(gateDir, "gate.toml") } });
const cert2 = join(dir, "rev-cert.pub");
writeFileSync(cert2, r2.certificate! + "\n");
const q = spawnSync("ssh-keygen", ["-Q", "-f", join(gateDir, "ssh", "sbc_revoked.krl"), cert2], { encoding: "utf8" });
check("sbc-gate sync → KRL: sshd would refuse the revoked certificate at login", (sync.status === 0 || sync.status === 2) && /REVOKED/.test(q.stdout + q.stderr), (q.stdout + q.stderr).trim().split(": ").pop());

// --------------------------------------------------------------- expiry
const ssh3 = await generateKeyMaterial();
const id3 = await c.requestAccess(agent, { resource_id: resourceId, action: "service.status:checkout-api", duration_secs: 60, uses: 3, ssh_public_key: sshPublicKeyLine(ssh3.publicKey), reason: "e2e: expiry check" });
const r3 = await until(id3, (x) => x.state === "Active" || x.state === "Failed");
check("gate: allowed inside the window", gate("systemctl status checkout-api", r3.certificate!).status === 0);
const waitMs = r3.valid_before * 1000 - Date.now() + 3000;
console.log(`  … waiting ${Math.ceil(waitMs / 1000)} s for the 60 s window to close`);
await sleep(Math.max(0, waitMs));
g = gate("systemctl status checkout-api", r3.certificate!);
check("gate: denied after expiry", g.status === 77 && /expired/.test(g.stderr), g.stderr.trim());
check("contract reports Expired from block time", (await c.request(id3))!.state === "Expired");

// --------------------------------------------------------------- cleanup
ownerCall("set_resource_status", { id: resourceId, status: "Disabled" });
const after = await c.overview();
check("audit chain advanced", after.audit_seq > ov.audit_seq, `seq ${ov.audit_seq} → ${after.audit_seq}, head ${after.audit_head.slice(0, 16)}…`);
summary();
console.log(`artifacts in ${dir}`);
void readFileSync;
