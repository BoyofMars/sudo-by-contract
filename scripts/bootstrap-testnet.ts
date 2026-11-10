// Bootstrap a Sudo by Contract deployment on NEAR testnet for the sandbox demo.
//
//   node scripts/bootstrap-testnet.ts --owner you.testnet --contract sbc.you.testnet [--deploy] [--admin you]
//
// Prerequisites (run by you, with your own NEAR CLI keychain):
//   1. A contract account you control, e.g.
//      near account create-account fund-myself sbc.you.testnet '8 NEAR' autogenerate-new-keypair \
//        save-to-legacy-keychain sign-as you.testnet network-config testnet sign-with-legacy-keychain send
//   2. The wasm: (cd contracts/sbc-policy && cargo near build non-reproducible-wasm --no-abi)
//
// Owner-signed calls go through the `near` CLI and your legacy keychain; this
// script never reads your account keys. The only keys it generates are
// one-time enrollment tokens and the demo agent's identity key, written to
// sandbox/.env (gitignored).

import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  SudoContract,
  generateKeyMaterial,
  publicKeyToString,
  secretKeyToString,
  signerFromKeyMaterial,
  type PolicyInput,
} from "../packages/sbc-client/src/index.ts";

const argv = process.argv.slice(2);
const opt = (name: string, def?: string) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : def;
};
const flag = (name: string) => argv.includes(`--${name}`);

const owner = opt("owner");
const contractId = opt("contract");
const network = opt("network", "testnet")!;
const mpc = opt("mpc", "v1.signer-prod.testnet")!;
const adminId = opt("admin", "tobi")!;
const adminLabel = opt("admin-label", "Tobi")!;
const consoleUrl = opt("console", "http://localhost:5180")!;
const rpcUrl = opt("rpc", "https://rpc.testnet.fastnear.com")!;
if (!owner || !contractId) {
  console.error("usage: node scripts/bootstrap-testnet.ts --owner <you>.testnet --contract <sbc>.<you>.testnet [--deploy] [--wasm path]");
  process.exit(2);
}

const root = resolve(import.meta.dirname, "..");
const near = (args: string[]) => execFileSync("near", args, { stdio: ["ignore", "inherit", "inherit"] });
const ownerCall = (method: string, args: object, tgas = 100) => {
  console.log(`\n→ ${method}`);
  near(["contract", "call-function", "as-transaction", contractId, method, "json-args", JSON.stringify(args),
    "prepaid-gas", `${tgas}.0 Tgas`, "attached-deposit", "0 NEAR", "sign-as", owner,
    "network-config", network, "sign-with-legacy-keychain", "send"]);
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const c = new SudoContract(contractId, rpcUrl);

if (flag("deploy")) {
  const wasm = opt("wasm") ??
    [join(root, "target/near/sbc_policy/sbc_policy.wasm"), join(process.env.CARGO_TARGET_DIR ?? "", "near/sbc_policy/sbc_policy.wasm")].find((p) => existsSync(p));
  if (!wasm || !existsSync(wasm)) throw new Error("wasm not found; build it or pass --wasm");
  console.log(`Deploying ${wasm} to ${contractId}`);
  near(["contract", "deploy", contractId, "use-file", wasm, "with-init-call", "new", "json-args",
    JSON.stringify({ owner, mpc_contract: mpc, mpc_domain_id: 1 }), "prepaid-gas", "100.0 Tgas",
    "attached-deposit", "0 NEAR", "network-config", network, "sign-with-legacy-keychain", "send"]);
}

// 1. environment + MPC-derived CA key
const ov = await c.overview();
if (!ov.environments.some((e) => e.name === "production")) ownerCall("add_environment", { name: "production" }, 60);
let ca: string | null = null;
for (let i = 0; i < 20 && !ca; i++) {
  ca = await c.ca("production");
  if (!ca) await sleep(1500);
}
if (!ca) throw new Error("production CA key did not arrive from the MPC contract");
console.log(`\n✓ production CA (derived by ${mpc} for ${contractId}):\n  ${ca}`);

// 2. identities
const approvers = await c.approvers();
if (!approvers.some((a) => a.id === adminId)) ownerCall("create_approver", { id: adminId, label: adminLabel, is_admin: true });
const agents = await c.agents();
if (!agents.some((a) => a.id === "deploy-agent")) {
  ownerCall("create_agent", { id: "deploy-agent", label: "Deploy Agent", owner: "platform-team", runtime: "sbc demo-agent (scripted)" });
}
const resources = await c.resources();
if (!resources.some((r) => r.id === "prod-web-02")) {
  ownerCall("create_resource", { id: "prod-web-02", label: "prod-web-02", environment: "production", tags: ["web"], services: ["checkout-api", "payments-api", "sshd"] });
}

// 3. policies — each maps onto a real gate adapter
const base = { description: "", conditions: { utc_hours: null, require_source_address: false } };
const policies: PolicyInput[] = [
  {
    ...base, id: "prod-remediation", name: "Production service remediation", effect: "Allow",
    description: "One restart of a customer-facing service, after a human approves it.",
    subjects: { all_agents: false, agents: ["deploy-agent"] },
    resources: { ids: [], environments: ["production"], tags: [] },
    actions: [{ kind: "service.restart", targets: ["checkout-api", "payments-api"] }],
    max_duration_secs: 900, max_uses: 1, approval: { required: 1, approvers: [] },
  },
  {
    ...base, id: "status-checks", name: "Service status checks", effect: "Allow",
    subjects: { all_agents: false, agents: ["deploy-agent"] },
    resources: { ids: [], environments: ["production"], tags: [] },
    actions: [{ kind: "service.status", targets: ["*"] }],
    max_duration_secs: 900, max_uses: 5, approval: { required: 0, approvers: [] },
  },
  {
    ...base, id: "log-inspection", name: "Log inspection", effect: "Allow",
    subjects: { all_agents: false, agents: ["deploy-agent"] },
    resources: { ids: [], environments: ["production"], tags: [] },
    actions: [{ kind: "logs.read", targets: ["*"] }],
    max_duration_secs: 900, max_uses: 10, approval: { required: 0, approvers: [] },
  },
  {
    ...base, id: "never-restart-sshd", name: "Never restart sshd", effect: "Deny",
    subjects: { all_agents: true, agents: [] },
    resources: { ids: [], environments: ["production"], tags: [] },
    actions: [{ kind: "service.restart", targets: ["sshd"] }],
    max_duration_secs: 900, max_uses: 1, approval: { required: 0, approvers: [] },
  },
];
for (const p of policies) ownerCall("upsert_policy", { policy: p });

// 4. one-time enrollment tokens
async function token(role: "Admin" | "Agent" | "Gate", principal: string, ttlSecs: number) {
  const k = await generateKeyMaterial();
  ownerCall("create_enrollment", { role, principal, token_public_key: publicKeyToString(k.publicKey), ttl_secs: ttlSecs }, 50);
  return k;
}

const gateToken = await token("Gate", "prod-web-02", 24 * 3600);
const agentToken = await token("Agent", "deploy-agent", 3600);
const adminToken = await token("Admin", adminId, 24 * 3600);

// The demo agent's identity key: generated here, bound by spending its token.
const agentKey = await generateKeyMaterial();
const enrolled = await c.completeEnrollment(await signerFromKeyMaterial(contractId, agentToken), publicKeyToString(agentKey.publicKey));
console.log(`\n✓ demo agent enrolled: ${JSON.stringify(enrolled)}`);

const envFile = join(root, "sandbox", ".env");
writeFileSync(
  envFile,
  [
    "# Generated by scripts/bootstrap-testnet.ts — contains one-time tokens and the demo agent key. Do not commit.",
    `SBC_CONTRACT=${contractId}`,
    `SBC_RPC=${rpcUrl}`,
    `SBC_RESOURCE=prod-web-02`,
    `SBC_ENROLL_TOKEN=${secretKeyToString(gateToken)}`,
    `SBC_AGENT_KEY=${secretKeyToString(agentKey)}`,
    `SBC_CONSOLE_URL=${consoleUrl}`,
    "",
  ].join("\n"),
  { mode: 0o600 },
);

const join_ = `${consoleUrl}/#/join?contract=${encodeURIComponent(contractId)}&token=${encodeURIComponent(secretKeyToString(adminToken))}`;
console.log(`
✓ Bootstrap complete. Wrote ${envFile}

Next:
  1. docker compose -f sandbox/docker-compose.yml up --build -d     (demo server enrolls itself)
  2. Open this link once to bind your browser as admin "${adminId}" (the token lives in the URL
     fragment, so it never reaches a server, and it is burned on first use):
       ${join_}
  3. docker compose -f sandbox/docker-compose.yml run --rm agent     (the hero demo)
`);
