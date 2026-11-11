// Typed client for the policy contract. Views need no key; every call is
// signed by a role key living on the contract account (or the owner account).

import { NearRpc, TGAS, type TxOutcome, type WaitUntil } from "./near.ts";
import type { Signer } from "./keys.ts";
import type * as T from "./types.ts";

/** Final approvals and auto-approved requests start MPC signing in the same transaction. */
export const SIGNING_GAS = 200n * TGAS;
export const DEFAULT_GAS = 50n * TGAS;

export class SudoContract {
  rpc: NearRpc;
  contractId: string;

  constructor(contractId: string, rpc: NearRpc | string = new NearRpc()) {
    this.contractId = contractId;
    this.rpc = typeof rpc === "string" ? new NearRpc(rpc) : rpc;
  }

  private view<R>(method: string, args: object = {}): Promise<R> {
    return this.rpc.view<R>(this.contractId, method, args);
  }

  private async call<R = unknown>(signer: Signer, method: string, args: object, gas = DEFAULT_GAS, waitUntil?: WaitUntil): Promise<R> {
    const out: TxOutcome = await this.rpc.functionCall(signer, this.contractId, method, args, { gas, waitUntil });
    return out.value as R;
  }

  // ----------------------------------------------------------------- views
  overview() { return this.view<T.Overview>("get_overview"); }
  ca(environment: string) { return this.view<string | null>("get_ca", { environment }); }
  whoami(publicKey: string) { return this.view<{ public_key: string; binding: T.KeyBinding | null }>("whoami", { public_key: publicKey }); }
  agents() { return this.view<T.Agent[]>("list_agents", {}); }
  agent(id: string) { return this.view<T.Agent | null>("get_agent", { id }); }
  approvers() { return this.view<T.Approver[]>("list_approvers", {}); }
  resources() { return this.view<T.Resource[]>("list_resources", {}); }
  resource(id: string) { return this.view<T.Resource | null>("get_resource", { id }); }
  policies() { return this.view<T.Policy[]>("list_policies", {}); }
  policy(id: string, version?: number) { return this.view<T.Policy | null>("get_policy", { id, version: version ?? null }); }
  describePolicy(id: string) { return this.view<string | null>("describe_policy", { id }); }
  policyProposals() { return this.view<T.PolicyProposal[]>("list_policy_proposals", {}); }
  request(id: number) { return this.view<T.AccessRequest | null>("get_request", { id }); }
  requests(q: { before_id?: number; limit?: number; agent_id?: string; resource_id?: string; states?: T.RequestState[] } = {}) {
    return this.view<T.AccessRequest[]>("list_requests", {
      before_id: q.before_id ?? null,
      limit: q.limit ?? null,
      agent_id: q.agent_id ?? null,
      resource_id: q.resource_id ?? null,
      states: q.states ?? null,
    });
  }
  revocations(resourceId: string) { return this.view<T.Revocation[]>("list_revocations", { resource_id: resourceId }); }
  simulate(a: { agent_id: string; resource_id: string; action: string; duration_secs: number; uses?: number; source_address?: string }) {
    return this.view<T.SimulateResult>("simulate", { uses: null, source_address: null, ...a });
  }

  // ---------------------------------------------------------------- agents
  /** Returns the request id. Auto-approved requests start signing: attach SIGNING_GAS. */
  requestAccess(agent: Signer, args: T.RequestAccessArgs) {
    return this.call<number>(agent, "request_access", { request: { uses: null, source_address: null, context_hash: null, ...args } }, SIGNING_GAS);
  }
  cancelRequest(agent: Signer, requestId: number) { return this.call(agent, "cancel_request", { request_id: requestId }); }

  // ------------------------------------------------------------- approvers
  /** The final approval starts MPC signing; don't wait for the signature by default. */
  approve(approver: Signer, requestId: number, maxDurationSecs?: number, waitUntil: WaitUntil = "INCLUDED_FINAL") {
    return this.call(approver, "approve", { request_id: requestId, max_duration_secs: maxDurationSecs ?? null }, SIGNING_GAS, waitUntil);
  }
  deny(approver: Signer, requestId: number, reason: string) { return this.call(approver, "deny", { request_id: requestId, reason }); }
  revoke(approver: Signer, requestId: number, reason: string) { return this.call(approver, "revoke", { request_id: requestId, reason }); }

  // ---------------------------------------------------------------- admins
  addEnvironment(admin: Signer, name: string) { return this.call(admin, "add_environment", { name }, 60n * TGAS); }
  createApprover(admin: Signer, id: string, label: string, isAdmin: boolean) { return this.call(admin, "create_approver", { id, label, is_admin: isAdmin }); }
  setApproverStatus(admin: Signer, id: string, status: T.Status) { return this.call(admin, "set_approver_status", { id, status }); }
  removeApprover(admin: Signer, id: string) { return this.call(admin, "remove_approver", { id }); }
  createAgent(admin: Signer, a: { id: string; label: string; owner: string; runtime: string }) { return this.call(admin, "create_agent", a); }
  setAgentStatus(admin: Signer, id: string, status: T.Status) { return this.call(admin, "set_agent_status", { id, status }); }
  createResource(admin: Signer, r: { id: string; label: string; environment: string; tags: string[]; services: string[] }) { return this.call(admin, "create_resource", r); }
  updateResource(admin: Signer, id: string, u: { label?: string; tags?: string[]; services?: string[] }) {
    return this.call(admin, "update_resource", { id, label: u.label ?? null, tags: u.tags ?? null, services: u.services ?? null });
  }
  setResourceStatus(admin: Signer, id: string, status: T.ResourceStatus) { return this.call(admin, "set_resource_status", { id, status }); }
  createEnrollment(admin: Signer, role: T.Role, principal: string, tokenPublicKey: string, ttlSecs = 3600) {
    return this.call(admin, "create_enrollment", { role, principal, token_public_key: tokenPublicKey, ttl_secs: ttlSecs }, 30n * TGAS);
  }
  removeKey(admin: Signer, publicKey: string) { return this.call(admin, "remove_key", { public_key: publicKey }, 30n * TGAS); }
  /** Returns the new version, or 0 when the change became a proposal awaiting the admin quorum. */
  upsertPolicy(admin: Signer, policy: T.PolicyInput) { return this.call<number>(admin, "upsert_policy", { policy }); }
  /** Returns the applied version once the quorum is met, else 0. */
  confirmPolicy(admin: Signer, proposalId: number) { return this.call<number>(admin, "confirm_policy", { proposal_id: proposalId }); }
  setPolicyStatus(admin: Signer, id: string, status: T.Status) { return this.call(admin, "set_policy_status", { id, status }); }

  // ------------------------------------------------------------ enrollment
  /** Signed with the one-time enrollment token; binds `newPublicKey` and burns the token. */
  completeEnrollment(token: Signer, newPublicKey: string, meta?: { gate_version?: string; host_fingerprint?: string }) {
    return this.call<T.EnrollResult>(token, "complete_enrollment", { new_public_key: newPublicKey, meta: meta ? { gate_version: meta.gate_version ?? null, host_fingerprint: meta.host_fingerprint ?? null } : null }, 50n * TGAS);
  }
}

/** Parse NEP-297 events out of a transaction outcome's logs. */
export function eventsFromOutcome(raw: any): T.ContractEvent[] {
  const out: T.ContractEvent[] = [];
  for (const ro of raw?.receipts_outcome ?? []) {
    for (const log of ro?.outcome?.logs ?? []) {
      if (typeof log === "string" && log.startsWith("EVENT_JSON:")) {
        try {
          const e = JSON.parse(log.slice("EVENT_JSON:".length));
          if (e.standard === "sudo-by-contract") out.push(e);
        } catch {
          /* ignore malformed */
        }
      }
    }
  }
  return out;
}
