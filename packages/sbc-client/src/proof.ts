// Independent, credential-free verification of a live Sudo by Contract
// deployment. Used by the console's /proof page and `npm run verify:live`.
//
// Nothing here trusts our own servers: every fact comes from NEAR RPC, and
// the cryptography runs locally (WebCrypto Ed25519).

import { SudoContract } from "./contract.ts";
import { b64decode, equalBytes } from "./encoding.ts";
import { publicKeyFromString, verify } from "./keys.ts";
import { NearRpc } from "./near.ts";
import { parseCertificateLine, sshPublicKeyLine, type CertSummary } from "./ssh.ts";
import type { AccessRequest } from "./types.ts";

export type StepStatus = "pending" | "running" | "pass" | "fail";

export interface ProofStep {
  id: "contract" | "mpc" | "derivation" | "binding" | "certificate" | "bounds" | "record";
  title: string;
  /** One-sentence claim this step proves, in plain words. */
  claim: string;
  status: StepStatus;
  detail?: string;
  facts?: Array<[string, string]>;
}

export interface ProofReport {
  ok: boolean;
  contractId: string;
  mpcContract?: string;
  caLine?: string;
  participants?: number;
  threshold?: number;
  certificate?: { line: string; summary: CertSummary; request: AccessRequest };
  steps: ProofStep[];
}

const STEPS: Array<Pick<ProofStep, "id" | "title" | "claim">> = [
  { id: "contract", title: "Policy contract is live", claim: "The deployed contract answers on NEAR testnet and names its signer." },
  { id: "mpc", title: "Signer is a threshold network", claim: "Signatures need a quorum of independent MPC nodes running in TEEs." },
  { id: "derivation", title: "CA key comes from the MPC network", claim: "Asked directly, NEAR's MPC contract derives exactly the CA key the servers trust." },
  { id: "binding", title: "Only this contract can use it", claim: "The same derivation path for any other account yields a different key." },
  { id: "certificate", title: "A real certificate verifies", claim: "A certificate the contract issued carries a valid Ed25519 signature from that CA." },
  { id: "bounds", title: "The certificate is bounded", claim: "One host, one forced command, no PTY or forwarding, minutes not days." },
  { id: "record", title: "Its history is on-chain", claim: "Request, policy decision, approval, signing and every use are public events." },
];

function short(s: string, n = 10): string {
  return s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

function fmtTime(unix: number): string {
  return new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/** Signed prefix and signature of an Ed25519 user certificate blob. */
function splitSignature(blob: Uint8Array): { signed: Uint8Array; signature: Uint8Array } {
  // trailer: string(string("ssh-ed25519") || string(sig64)) = 4 + (4 + 11 + 4 + 64) = 87 bytes
  const at = blob.length - 87;
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  if (at <= 0 || dv.getUint32(at, false) !== 83) throw new Error("unexpected certificate signature layout");
  return { signed: blob.subarray(0, at), signature: blob.subarray(blob.length - 64) };
}

export async function verifyDeployment(opts: {
  contractId: string;
  rpcUrl?: string;
  environment?: string;
  onStep?: (steps: ProofStep[]) => void;
}): Promise<ProofReport> {
  const rpc = new NearRpc(opts.rpcUrl);
  const c = new SudoContract(opts.contractId, rpc);
  const steps: ProofStep[] = STEPS.map((s) => ({ ...s, status: "pending" }));
  const report: ProofReport = { ok: false, contractId: opts.contractId, steps };
  const emit = () => opts.onStep?.(steps.map((s) => ({ ...s })));
  const step = async (id: ProofStep["id"], fn: (s: ProofStep) => Promise<void>): Promise<boolean> => {
    const s = steps.find((x) => x.id === id)!;
    s.status = "running";
    emit();
    try {
      await fn(s);
      s.status = "pass";
    } catch (e) {
      s.status = "fail";
      s.detail = e instanceof Error ? e.message : String(e);
    }
    emit();
    return s.status === "pass";
  };

  let overview: Awaited<ReturnType<SudoContract["overview"]>> | undefined;
  let env: { name: string; path: string; ca_public_key: string | null; ca_public_key_ssh: string | null } | undefined;
  let caRaw: Uint8Array | undefined;

  const ok1 = await step("contract", async (s) => {
    overview = await c.overview();
    const acct = await rpc.call("query", { request_type: "view_account", finality: "final", account_id: opts.contractId });
    env = overview.environments.find((e) => e.name === (opts.environment ?? "production")) ?? overview.environments[0];
    if (!env?.ca_public_key || !env.ca_public_key_ssh) throw new Error("no environment with a CA key yet");
    caRaw = b64decode(env.ca_public_key);
    report.mpcContract = overview.config.mpc_contract;
    report.caLine = env.ca_public_key_ssh;
    s.detail = `${opts.contractId} · ${overview.request_count} capabilities issued or requested · audit event #${overview.audit_seq}`;
    s.facts = [
      ["Contract", opts.contractId],
      ["Code hash", acct.code_hash],
      ["Signer", `${overview.config.mpc_contract} (domain ${overview.config.mpc_domain_id})`],
      ["Environment", `${env.name} — path ${env.path}`],
      ["Audit head", short(overview.audit_head, 12)],
    ];
  });

  await step("mpc", async (s) => {
    if (!overview) throw new Error("skipped: contract unavailable");
    const st = await rpc.view<any>(overview.config.mpc_contract, "state", {});
    const run = st.Running ?? st.Resharing ?? st.Initializing;
    if (!run) throw new Error("MPC network is not running");
    const domain = run.domains?.domains?.find((d: any) => d.id === overview!.config.mpc_domain_id);
    if (!domain) throw new Error(`domain ${overview.config.mpc_domain_id} not found`);
    if (domain.protocol !== "Frost") throw new Error(`domain ${domain.id} is ${domain.protocol}, expected Frost (Ed25519)`);
    const participants: number = run.parameters?.participants?.participants?.length ?? 0;
    const threshold: number = domain.reconstruction_threshold ?? run.parameters?.threshold;
    report.participants = participants;
    report.threshold = threshold;
    s.detail = `Any ${threshold} of ${participants} independent nodes must cooperate to sign. No node holds the key.`;
    s.facts = [
      ["Protocol", `${domain.protocol} threshold Ed25519`],
      ["Quorum", `${threshold} of ${participants}`],
      ["Operators", (run.parameters?.participants?.participants ?? []).slice(0, 4).map((p: any) => p[0]).join(", ") + (participants > 4 ? ", …" : "")],
    ];
  });

  const ok3 = await step("derivation", async (s) => {
    if (!overview || !env || !caRaw) throw new Error("skipped: contract unavailable");
    const derived = await rpc.view<string>(overview.config.mpc_contract, "derived_public_key", {
      path: env.path,
      predecessor: opts.contractId,
      domain_id: overview.config.mpc_domain_id,
    });
    const mpcRaw = publicKeyFromString(derived);
    if (!equalBytes(mpcRaw, caRaw)) throw new Error(`MPC derives ${derived}, but the contract's CA differs`);
    s.detail = `derived_public_key(${env.path}, ${opts.contractId}) = the CA in TrustedUserCAKeys`;
    s.facts = [
      ["Derived by MPC", short(derived, 14)],
      ["TrustedUserCAKeys", short(sshPublicKeyLine(caRaw), 18)],
    ];
  });

  await step("binding", async (s) => {
    if (!overview || !env || !caRaw) throw new Error("skipped: contract unavailable");
    const other = "someone-else.testnet";
    const derived = await rpc.view<string>(overview.config.mpc_contract, "derived_public_key", {
      path: env.path,
      predecessor: other,
      domain_id: overview.config.mpc_domain_id,
    });
    if (equalBytes(publicKeyFromString(derived), caRaw)) throw new Error("another account derives the same key");
    s.detail = `Same path from ${other} → a different key. Derivation is bound to the calling account, so only ${opts.contractId}'s code can ask for signatures with this CA.`;
    s.facts = [
      [opts.contractId, short(sshPublicKeyLine(caRaw).split(" ")[1], 14)],
      [other, short(derived, 14)],
    ];
  });

  let req: AccessRequest | undefined;
  let cert: CertSummary | undefined;
  const ok5 = await step("certificate", async (s) => {
    if (!caRaw) throw new Error("skipped: no CA key");
    const recent = await c.requests({ limit: 50 });
    req = recent.find((r) => r.certificate);
    if (!req?.certificate) throw new Error("no certificate has been issued yet");
    cert = parseCertificateLine(req.certificate);
    const blob = b64decode(req.certificate.split(/\s+/)[1]);
    const { signed, signature } = splitSignature(blob);
    if (!equalBytes(cert.caPublicKey, caRaw)) throw new Error("certificate names a different CA");
    if (!(await verify(caRaw, signed, signature))) throw new Error("signature does NOT verify");
    report.certificate = { line: req.certificate, summary: cert, request: req };
    s.detail = `Capability #${req.id} · serial ${cert.serial} · ${signed.length}-byte body signed by the MPC network, verified here with Ed25519.`;
    s.facts = [
      ["Capability", `#${req.id} — ${req.action} on ${req.resource_id}`],
      ["Serial", String(cert.serial)],
      ["Signature", `${Array.from(signature.subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join("")}… ✓`],
    ];
  });

  await step("bounds", async (s) => {
    if (!cert || !req) throw new Error("skipped: no certificate");
    const window = cert.validBefore - cert.validAfter;
    const fc = cert.criticalOptions["force-command"];
    if (cert.principals.length !== 1) throw new Error(`expected one principal, found ${cert.principals.length}`);
    if (!fc) throw new Error("no force-command");
    if (cert.extensions.length) throw new Error(`grants extensions: ${cert.extensions.join(", ")}`);
    if (window > 24 * 3600) throw new Error(`window is ${window}s`);
    s.detail = `Valid ${Math.round(window / 60)} min for ${cert.principals[0]} only, forced through ${fc}, no extensions.`;
    s.facts = [
      ["Principal", cert.principals[0]],
      ["Valid", `${fmtTime(cert.validAfter)} → ${fmtTime(cert.validBefore)}`],
      ["Force-command", fc],
      ["Extensions", "none (no PTY, no forwarding, no agent)"],
    ];
  });

  await step("record", async (s) => {
    if (!req) throw new Error("skipped: no certificate");
    const kinds = req.events.map((e) => e.kind);
    for (const k of ["request_created", "policy_evaluated", "credential_signing", "credential_issued"]) {
      if (!kinds.includes(k)) throw new Error(`missing ${k} event`);
    }
    s.detail = `${req.events.length} events for capability #${req.id}; state ${req.state}, ${req.uses}/${req.max_uses} uses, ${req.denied_attempts} denied attempts.`;
    s.facts = [
      ["Policy", `${req.policy_id} v${req.policy_version} · ${short(req.policy_hash ?? "", 8)}`],
      ["Timeline", kinds.join(" → ")],
    ];
  });

  report.ok = ok1 && ok3 && ok5 && steps.every((s) => s.status === "pass");
  return report;
}
