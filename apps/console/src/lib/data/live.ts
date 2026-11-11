// Live data: views straight from the policy contract over NEAR RPC, writes
// signed by this browser's non-extractable device key, private context and
// gate reports from the relay.

import {
  NearRpc,
  SudoContract,
  generateDeviceKey,
  generateKeyMaterial,
  publicKeyToString,
  secretKeyToString,
  signerFromCryptoKeyPair,
  signerFromSecretString,
  type EnrollResult,
  type PolicyInput,
  type ResourceStatus,
  type Role,
  type Signer,
  type Status,
} from "@sbc/client";
import { deleteDeviceKey, loadDeviceKey, saveDeviceKey } from "../devicekey.ts";
import { RelayClient, type ContextRecord, type GateReport } from "../relay.ts";
import { networkOf } from "../config.ts";
import { isFixtureId, type DataSource, type EnrollmentToken, type FixtureSummary, type Identity, type RelayState, type RequestQuery } from "./source.ts";

const FIXTURES_KEY = "sbc.showFixtures";
function readShowFixtures(): boolean {
  try {
    return localStorage.getItem(FIXTURES_KEY) === "1";
  } catch {
    return false;
  }
}

export class LiveSource implements DataSource {
  readonly mode = "live" as const;
  readonly contractId: string;
  readonly rpcUrl: string;
  readonly relayUrl: string | null;
  readonly network: "testnet" | "mainnet" | "preview";
  private c: SudoContract;
  private signerP: Promise<Signer | null> | null = null;
  private relayStateCache: { at: number; v: RelayState } | null = null;

  constructor(contractId: string, rpcUrl: string, relayUrl: string | null) {
    this.contractId = contractId;
    this.rpcUrl = rpcUrl;
    this.relayUrl = relayUrl;
    this.network = networkOf(contractId);
    this.c = new SudoContract(contractId, new NearRpc(rpcUrl));
  }

  private signer(): Promise<Signer | null> {
    if (!this.signerP) {
      this.signerP = loadDeviceKey(this.contractId).then((kp) => (kp ? signerFromCryptoKeyPair(this.contractId, kp) : null));
    }
    return this.signerP;
  }

  private async must(): Promise<Signer> {
    const s = await this.signer();
    if (!s) throw new Error("no device key");
    return s;
  }

  private async relay(): Promise<RelayClient | null> {
    if (!this.relayUrl) return null;
    return new RelayClient(this.relayUrl, await this.signer());
  }

  // Fixtures stay on-chain and reachable by direct link (request ids, agent
  // and resource pages); they are only left out of lists by default.
  showFixtures = readShowFixtures();
  setShowFixtures(show: boolean) {
    this.showFixtures = show;
    try {
      localStorage.setItem(FIXTURES_KEY, show ? "1" : "0");
    } catch {
      /* per-browser convenience only */
    }
  }
  async fixtureSummary(): Promise<FixtureSummary> {
    const [res, appr, ag, reqs] = await Promise.all([this.c.resources(), this.c.approvers(), this.c.agents(), this.c.requests({ limit: 100 })]);
    return {
      resources: res.filter((r) => isFixtureId(r.id)).length,
      approvers: appr.filter((a) => isFixtureId(a.id)).length,
      agents: ag.filter((a) => isFixtureId(a.id)).length,
      requests: reqs.filter((r) => isFixtureId(r.resource_id) || isFixtureId(r.agent_id)).length,
    };
  }
  private keep<T>(items: T[], ...ids: ((t: T) => string)[]): T[] {
    return this.showFixtures ? items : items.filter((t) => !ids.some((id) => isFixtureId(id(t))));
  }

  overview() { return this.c.overview(); }
  async requests(q: RequestQuery = {}) { return this.keep(await this.c.requests(q), (r) => r.resource_id, (r) => r.agent_id); }
  request(id: number) { return this.c.request(id); }
  async agents() { return this.keep(await this.c.agents(), (a) => a.id); }
  async approvers() { return this.keep(await this.c.approvers(), (a) => a.id); }
  async resources() { return this.keep(await this.c.resources(), (r) => r.id); }
  policies() { return this.c.policies(); }
  policy(id: string, version?: number) { return this.c.policy(id, version); }
  simulate(a: Parameters<SudoContract["simulate"]>[0]) { return this.c.simulate(a); }

  async identity(): Promise<Identity> {
    const s = await this.signer();
    if (!s) return { publicKey: null, binding: null };
    const pk = publicKeyToString(s.publicKey);
    const w = await this.c.whoami(pk);
    return { publicKey: pk, binding: w.binding, unbound: !w.binding };
  }

  async relayState(): Promise<RelayState> {
    if (!this.relayUrl) return "unconfigured";
    if (this.relayStateCache && Date.now() - this.relayStateCache.at < 30_000) return this.relayStateCache.v;
    const ok = await new RelayClient(this.relayUrl, null).health();
    const v: RelayState = ok ? "ok" : "unavailable";
    this.relayStateCache = { at: Date.now(), v };
    return v;
  }

  async context(hash: string): Promise<ContextRecord | null> {
    const r = await this.relay();
    if (!r || !(await this.signer())) return null;
    try {
      return await r.context(hash);
    } catch {
      return null;
    }
  }

  async gateReports(q: { request_id?: number; resource_id?: string; limit?: number }): Promise<GateReport[]> {
    const r = await this.relay();
    if (!r || !(await this.signer())) return [];
    try {
      return await r.gateReports(q);
    } catch {
      return [];
    }
  }

  subscribe(cb: Parameters<DataSource["subscribe"]>[0]): () => void {
    let stop: (() => void) | null = null;
    let cancelled = false;
    this.relay().then(async (r) => {
      if (!r || cancelled) return;
      try {
        const s = await r.subscribe((e) => cb(e));
        if (cancelled) s();
        else stop = s;
      } catch {
        /* relay optional: pages poll anyway */
      }
    });
    return () => {
      cancelled = true;
      stop?.();
    };
  }

  async approve(id: number, maxDurationSecs?: number) { await this.c.approve(await this.must(), id, maxDurationSecs); }
  async deny(id: number, reason: string) { await this.c.deny(await this.must(), id, reason); }
  async revoke(id: number, reason: string) { await this.c.revoke(await this.must(), id, reason); }
  async createAgent(a: { id: string; label: string; owner: string; runtime: string }) { await this.c.createAgent(await this.must(), a); }
  async setAgentStatus(id: string, status: Status) { await this.c.setAgentStatus(await this.must(), id, status); }
  async createApprover(id: string, label: string, isAdmin: boolean) { await this.c.createApprover(await this.must(), id, label, isAdmin); }
  async setApproverStatus(id: string, status: Status) { await this.c.setApproverStatus(await this.must(), id, status); }
  async createResource(r: { id: string; label: string; environment: string; tags: string[]; services: string[] }) { await this.c.createResource(await this.must(), r); }
  async setResourceStatus(id: string, status: ResourceStatus) { await this.c.setResourceStatus(await this.must(), id, status); }
  async addEnvironment(name: string) { await this.c.addEnvironment(await this.must(), name); }
  async upsertPolicy(p: PolicyInput) { return (await this.c.upsertPolicy(await this.must(), p)) as number; }
  async setPolicyStatus(id: string, status: Status) { await this.c.setPolicyStatus(await this.must(), id, status); }
  policyProposals() { return this.c.policyProposals(); }
  async confirmPolicy(proposalId: number) { return ((await this.c.confirmPolicy(await this.must(), proposalId)) as number) ?? 0; }

  async createEnrollment(role: Role, principal: string, ttlSecs = 3600): Promise<EnrollmentToken> {
    const km = await generateKeyMaterial();
    const tokenPublicKey = publicKeyToString(km.publicKey);
    await this.c.createEnrollment(await this.must(), role, principal, tokenPublicKey, ttlSecs);
    return { token: secretKeyToString(km), tokenPublicKey, expiresAtMs: Date.now() + ttlSecs * 1000 };
  }

  async enrollDevice(token: string): Promise<EnrollResult> {
    const tokenSigner = await signerFromSecretString(this.contractId, token.trim());
    const kp = await generateDeviceKey();
    const device = await signerFromCryptoKeyPair(this.contractId, kp);
    const res = await this.c.completeEnrollment(tokenSigner, publicKeyToString(device.publicKey));
    if (res?.ok) {
      await saveDeviceKey(this.contractId, kp);
      this.signerP = Promise.resolve(device);
    }
    return res;
  }

  async forgetDevice() {
    await deleteDeviceKey(this.contractId);
    this.signerP = Promise.resolve(null);
  }
}
