// SudoAgent: the agent-side half of "Request → Evaluate → Approve → Issue →
// Execute → Observe → Expire".
//
// The agent never holds a reusable credential. Each request gets a fresh
// Ed25519 SSH key generated here; the contract binds a short-lived, single-host,
// force-commanded certificate to it once policy and humans agree; the host gate
// re-checks every execution with the contract. Releasing (or expiry) ends it.

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  LIVE_STATES,
  NearRpc,
  RpcError,
  SudoContract,
  b64encode,
  generateKeyMaterial,
  opensshPrivateKey,
  publicKeyToString,
  signerFromSecretString,
  sshPublicKeyLine,
  splitAction,
  type AccessRequest,
  type Check,
  type RequestState,
  type Resource,
  type Signer,
  type SimulateResult,
} from "../../sbc-client/src/index.ts";
import { parseDuration } from "./duration.ts";
import { ensureDir, writePrivateFile } from "./files.ts";
import { RelayClient, type ContextDocument } from "./relay-client.ts";
import { buildSshArgv, parseSshTarget, runSsh, type ExecResult } from "./ssh-exec.ts";

/** The subset of SudoContract the SDK needs (lets tests inject a stub). */
export type ContractLike = Pick<
  SudoContract,
  "requestAccess" | "request" | "requests" | "cancelRequest" | "simulate" | "whoami" | "resources" | "resource"
>;

export interface RelayLike {
  postContext(doc: ContextDocument): Promise<string>;
}

export interface SudoAgentOptions {
  contractId: string;
  rpcUrl?: string;
  relayUrl?: string;
  /** `ed25519:<base58>` (NEAR CLI format). The key is an access key on the contract account. */
  agentSecretKey: string;
  /** Where ephemeral session keys and certificates are written. */
  stateDir: string;
  /** Test seams. */
  contract?: ContractLike;
  relay?: RelayLike;
  sshBinary?: string;
  pollIntervalMs?: number;
  /** Non-fatal problems, e.g. the relay was unreachable and evidence stayed local. */
  onWarning?: (message: string) => void;
}

export type ActionSpec = string | { kind: string; target: string };

export interface RequestOptions {
  resource: string;
  action: ActionSpec;
  duration: string | number;
  uses?: number;
  reason: string;
  evidence?: Array<{ label: string; value: string }>;
  links?: Array<{ label: string; url: string }>;
  sourceAddress?: string;
}

const ACTION_KINDS = new Set(["service.restart", "service.status", "logs.read"]);

export function normalizeAction(a: ActionSpec): string {
  const canonical = typeof a === "string" ? a : `${a.kind}:${a.target}`;
  const { kind, target } = splitAction(canonical);
  if (!ACTION_KINDS.has(kind)) throw new Error(`unknown action kind "${kind}" (expected service.restart, service.status or logs.read)`);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,99}$/.test(target) || target.includes("..")) throw new Error(`invalid target "${target}"`);
  return `${kind}:${target}`;
}

/** Thrown when a capability ends without becoming usable (rejected, denied, failed, ...). */
export class CapabilityError extends Error {
  state: RequestState;
  stateReason: string | null;
  failedChecks: Check[];
  request: AccessRequest | null;
  constructor(message: string, request: AccessRequest | null, state: RequestState) {
    super(message);
    this.name = "CapabilityError";
    this.request = request;
    this.state = state;
    this.stateReason = request?.state_reason ?? null;
    this.failedChecks = (request?.checks ?? []).filter((c) => !c.ok);
  }
}

export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimeoutError";
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class Capability {
  readonly id: number;
  readonly dir: string;
  readonly keyPath: string;
  readonly certPath: string;
  private agent: SudoAgent;
  last: AccessRequest | null = null;

  constructor(agent: SudoAgent, id: number, dir: string) {
    this.agent = agent;
    this.id = id;
    this.dir = dir;
    this.keyPath = join(dir, "id_ed25519");
    this.certPath = join(dir, "id_ed25519-cert.pub");
  }

  async state(): Promise<AccessRequest> {
    const r = await this.agent.contract.request(this.id);
    if (!r) throw new Error(`request ${this.id} does not exist on ${this.agent.contractId}`);
    this.last = r;
    if (r.state === "Active" && r.certificate && !existsSync(this.certPath)) this.writeCertificate(r.certificate);
    return r;
  }

  private writeCertificate(line: string) {
    writeFileSync(this.certPath, line.trim() + "\n", { mode: 0o644 });
  }

  /**
   * Poll until the capability is Active (certificate written next to the key)
   * or reaches a terminal state, which throws a CapabilityError.
   */
  async wait(opts: { onState?: (r: AccessRequest) => void; timeoutMs?: number; pollMs?: number } = {}): Promise<AccessRequest> {
    const deadline = Date.now() + (opts.timeoutMs ?? 20 * 60_000);
    const poll = opts.pollMs ?? this.agent.pollIntervalMs;
    let lastState: string | null = null;
    for (;;) {
      let r: AccessRequest;
      try {
        r = await this.state();
      } catch (e) {
        if (e instanceof RpcError && Date.now() < deadline) {
          await sleep(poll);
          continue;
        }
        throw e;
      }
      if (r.state !== lastState) {
        lastState = r.state;
        opts.onState?.(r);
      }
      if (r.state === "Active") {
        if (!r.certificate) throw new CapabilityError("capability is Active but carries no certificate", r, r.state);
        this.writeCertificate(r.certificate);
        return r;
      }
      if (!LIVE_STATES.includes(r.state)) {
        throw new CapabilityError(`capability #${r.id} ended as ${r.state}${r.state_reason ? `: ${r.state_reason}` : ""}`, r, r.state);
      }
      if (Date.now() >= deadline) throw new TimeoutError(`capability #${this.id} still ${r.state} after waiting`);
      await sleep(poll);
    }
  }

  /** Milliseconds of authority left (0 unless Active). */
  remaining(r: AccessRequest | null = this.last): number {
    if (!r || r.state !== "Active") return 0;
    return Math.max(0, r.valid_before * 1000 - Date.now());
  }

  /** argv for `ssh` — exposed for tests and for callers who want to stream themselves. */
  sshArgv(command: string, target: { host: string; user?: string; port?: number } | string): string[] {
    const t = typeof target === "string" ? parseSshTarget(target) : { user: target.user ?? "sbc-agent", host: target.host, port: target.port ?? 22 };
    return buildSshArgv({
      keyPath: this.keyPath,
      certPath: this.certPath,
      knownHostsPath: join(this.agent.stateDir, "known_hosts"),
      target: t,
      command,
    });
  }

  /**
   * Run one command on the resource. The gate on the host decides; a denial
   * comes back as a non-zero exit code with the gate's explanation on stderr.
   */
  async exec(
    command: string | string[],
    target: { host: string; user?: string; port?: number } | string,
    opts: { timeoutMs?: number; onStdout?: (s: string) => void; onStderr?: (s: string) => void } = {},
  ): Promise<ExecResult> {
    const cmd = Array.isArray(command) ? command.join(" ") : command;
    if (!existsSync(this.certPath)) {
      const r = await this.state();
      if (!r.certificate) throw new CapabilityError(`capability #${this.id} has no certificate (state ${r.state})`, r, r.state);
      this.writeCertificate(r.certificate);
    }
    return runSsh(this.sshArgv(cmd, target), { sshBinary: this.agent.sshBinary, ...opts });
  }

  /** Give the authority back before it expires. */
  async release(): Promise<void> {
    await this.agent.contract.cancelRequest(await this.agent.signer(), this.id);
  }
}

export class SudoAgent {
  readonly contractId: string;
  readonly stateDir: string;
  readonly contract: ContractLike;
  readonly pollIntervalMs: number;
  readonly sshBinary?: string;
  private secret: string;
  private relayUrl?: string;
  private relayOverride?: RelayLike;
  private signerP?: Promise<Signer>;
  private agentIdP?: Promise<string>;
  private warn: (message: string) => void;

  constructor(o: SudoAgentOptions) {
    this.warn = o.onWarning ?? ((m) => console.warn(`sbc-agent: ${m}`));
    this.contractId = o.contractId;
    this.stateDir = o.stateDir;
    this.secret = o.agentSecretKey;
    this.relayUrl = o.relayUrl;
    this.relayOverride = o.relay;
    this.sshBinary = o.sshBinary;
    this.pollIntervalMs = o.pollIntervalMs ?? 2000;
    this.contract = o.contract ?? new SudoContract(o.contractId, new NearRpc(o.rpcUrl));
    ensureDir(join(this.stateDir, "sessions"));
  }

  signer(): Promise<Signer> {
    // role keys live on the contract account itself
    this.signerP ??= signerFromSecretString(this.contractId, this.secret);
    return this.signerP;
  }

  async publicKey(): Promise<string> {
    return publicKeyToString((await this.signer()).publicKey);
  }

  /** The agent id this key is bound to on-chain (fails if the key is not an Agent key). */
  agentId(): Promise<string> {
    this.agentIdP ??= (async () => {
      const w = await this.contract.whoami(await this.publicKey());
      if (!w.binding) throw new Error(`key ${w.public_key} is not enrolled on ${this.contractId}`);
      if (w.binding.role !== "Agent") throw new Error(`key ${w.public_key} has role ${w.binding.role}, not Agent`);
      return w.binding.principal;
    })();
    this.agentIdP.catch(() => (this.agentIdP = undefined));
    return this.agentIdP;
  }

  private relay(): RelayLike | null {
    if (this.relayOverride) return this.relayOverride;
    if (!this.relayUrl) return null;
    const url = this.relayUrl;
    return {
      postContext: async (doc) => new RelayClient(url, await this.signer()).postContext(doc),
    };
  }

  listResources(): Promise<Resource[]> {
    return this.contract.resources();
  }

  async simulate(o: { resource: string; action: ActionSpec; duration: string | number; uses?: number; sourceAddress?: string }): Promise<SimulateResult> {
    return this.contract.simulate({
      agent_id: await this.agentId(),
      resource_id: o.resource,
      action: normalizeAction(o.action),
      duration_secs: parseDuration(o.duration),
      uses: o.uses,
      source_address: o.sourceAddress,
    });
  }

  /**
   * Ask for one capability. Returns as soon as the request is on-chain; call
   * `wait()` for approval and issuance.
   */
  async request(o: RequestOptions): Promise<Capability> {
    const action = normalizeAction(o.action);
    const duration = parseDuration(o.duration);
    const signer = await this.signer();

    // 1. a fresh key for this capability only
    const key = await generateKeyMaterial();
    const pending = join(this.stateDir, "sessions", `pending-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    ensureDir(pending);
    writePrivateFile(join(pending, "id_ed25519"), opensshPrivateKey(key, `sbc-ephemeral ${action}`));
    writeFileSync(join(pending, "id_ed25519.pub"), sshPublicKeyLine(key.publicKey, "sbc-ephemeral") + "\n");

    // 2. private context (evidence, full rationale) stays off-chain; only its hash goes on-chain.
    //    The relay is never in the authorisation path: if it is down, the
    //    request goes ahead with its on-chain reason and no evidence link.
    let contextHash: string | null = null;
    const relay = this.relay();
    if (relay) {
      try {
        contextHash = await relay.postContext({ rationale: o.reason, evidence: o.evidence ?? [], ...(o.links ? { links: o.links } : {}) });
      } catch (e) {
        this.warn(`relay unavailable (${e instanceof Error ? e.message : e}); requesting without private evidence`);
      }
    }

    // 3. the on-chain request
    const sshPublicKey = b64encode(key.publicKey);
    let id: number;
    try {
      id = await this.contract.requestAccess(signer, {
        resource_id: o.resource,
        action,
        duration_secs: duration,
        uses: o.uses ?? 1,
        ssh_public_key: sshPublicKey,
        source_address: o.sourceAddress ?? null,
        reason: o.reason.length > 280 ? o.reason.slice(0, 277) + "…" : o.reason,
        context_hash: contextHash,
      });
    } catch (e) {
      // Auto-approved requests wait for the MPC signature inside the same
      // transaction; if the RPC gives up first, find our request by its key.
      if (!(e instanceof RpcError) || !/TIMEOUT|timeout/i.test(e.message)) throw e;
      id = await this.findRequestByKey(sshPublicKey);
    }
    if (typeof id !== "number") throw new Error("request_access returned no id");

    const dir = join(this.stateDir, "sessions", String(id));
    renameSync(pending, dir);
    writeFileSync(
      join(dir, "meta.json"),
      JSON.stringify({ id, contract: this.contractId, resource: o.resource, action, duration_secs: duration, created_at_ms: Date.now(), context_hash: contextHash }, null, 2),
    );
    return new Capability(this, id, dir);
  }

  private async findRequestByKey(sshPublicKey: string): Promise<number> {
    const agentId = await this.agentId();
    for (let i = 0; i < 30; i++) {
      const rs = await this.contract.requests({ agent_id: agentId, limit: 10 });
      const hit = rs.find((r) => r.ssh_public_key === sshPublicKey);
      if (hit) return hit.id;
      await sleep(2000);
    }
    throw new Error("request was sent but could not be found on-chain");
  }

  /** Re-open a capability created earlier (by id) from the state directory. */
  capability(id: number): Capability {
    const dir = join(this.stateDir, "sessions", String(id));
    if (!existsSync(join(dir, "id_ed25519"))) throw new Error(`no local key for capability #${id} in ${dir}`);
    return new Capability(this, id, dir);
  }

  sessionMeta(id: number): { id: number; resource: string; action: string } | null {
    const p = join(this.stateDir, "sessions", String(id), "meta.json");
    return existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
  }
}
