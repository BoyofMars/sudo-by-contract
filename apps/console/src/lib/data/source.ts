// The one interface every page talks to. `LiveSource` is the NEAR contract +
// relay; `PreviewSource` is an in-memory simulation of the same state machine.

import type {
  AccessRequest,
  Agent,
  Approver,
  EnrollResult,
  KeyBinding,
  Overview,
  Policy,
  PolicyInput,
  PolicyProposal,
  RequestState,
  Resource,
  ResourceStatus,
  Role,
  SimulateResult,
  Status,
} from "@sbc/client";
import type { ContextRecord, GateReport, RelayEvent } from "../relay.ts";

export type Mode = "live" | "preview";

export interface Identity {
  publicKey: string | null;
  binding: KeyBinding | null;
  /** The device key exists but is not (or no longer) bound on the contract. */
  unbound?: boolean;
}

export interface RequestQuery {
  before_id?: number;
  limit?: number;
  agent_id?: string;
  resource_id?: string;
  states?: RequestState[];
}

export interface EnrollmentToken {
  token: string;
  tokenPublicKey: string;
  expiresAtMs: number;
}

export type RelayState = "ok" | "unavailable" | "unconfigured";

/** Identities and hosts created by `scripts/e2e-testnet.ts` are named `e2e-…`. */
export const isFixtureId = (id: string | null | undefined) => !!id && id.startsWith("e2e-");

export interface FixtureSummary {
  resources: number;
  approvers: number;
  agents: number;
  requests: number;
}

export interface DataSource {
  readonly mode: Mode;
  readonly contractId: string;
  readonly rpcUrl: string;
  readonly relayUrl: string | null;
  readonly network: "testnet" | "mainnet" | "preview";

  overview(): Promise<Overview>;
  requests(q?: RequestQuery): Promise<AccessRequest[]>;
  request(id: number): Promise<AccessRequest | null>;
  agents(): Promise<Agent[]>;
  approvers(): Promise<Approver[]>;
  resources(): Promise<Resource[]>;
  policies(): Promise<Policy[]>;
  policy(id: string, version?: number): Promise<Policy | null>;
  simulate(a: { agent_id: string; resource_id: string; action: string; duration_secs: number; uses?: number; source_address?: string }): Promise<SimulateResult>;
  identity(): Promise<Identity>;

  /** Test fixtures from the live end-to-end run: hidden from lists unless shown. */
  readonly showFixtures?: boolean;
  setShowFixtures?(show: boolean): void;
  fixtureSummary?(): Promise<FixtureSummary>;

  relayState(): Promise<RelayState>;
  context(hash: string): Promise<ContextRecord | null>;
  gateReports(q: { request_id?: number; resource_id?: string; limit?: number }): Promise<GateReport[]>;
  subscribe(cb: (e: RelayEvent | { type: "changed" }) => void): () => void;

  approve(id: number, maxDurationSecs?: number): Promise<void>;
  deny(id: number, reason: string): Promise<void>;
  revoke(id: number, reason: string): Promise<void>;

  createAgent(a: { id: string; label: string; owner: string; runtime: string }): Promise<void>;
  setAgentStatus(id: string, status: Status): Promise<void>;
  createApprover(id: string, label: string, isAdmin: boolean): Promise<void>;
  setApproverStatus(id: string, status: Status): Promise<void>;
  createResource(r: { id: string; label: string; environment: string; tags: string[]; services: string[] }): Promise<void>;
  setResourceStatus(id: string, status: ResourceStatus): Promise<void>;
  addEnvironment(name: string): Promise<void>;
  createEnrollment(role: Role, principal: string, ttlSecs?: number): Promise<EnrollmentToken>;
  /** New version number, or 0 when the change became a proposal awaiting the admin quorum. */
  upsertPolicy(p: PolicyInput): Promise<number>;
  setPolicyStatus(id: string, status: Status): Promise<void>;
  policyProposals(): Promise<PolicyProposal[]>;
  /** Applied version once the quorum is met, else 0. */
  confirmPolicy(proposalId: number): Promise<number>;

  /** Join with an enrollment token: create a non-extractable device key and bind it. */
  enrollDevice(token: string): Promise<EnrollResult>;
  forgetDevice(): Promise<void>;
}

/** Turn contract panics and RPC errors into something a human can act on. */
export function friendlyError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/not bound to any identity/.test(msg)) return "This device key is not enrolled on the contract (it may have been removed). Join again with a fresh enrollment link.";
  if (/is not on .* \(not enrolled, or removed\)/.test(msg)) return "This device's access key is not on the contract account. Join again with a fresh enrollment link.";
  if (/no device key/i.test(msg)) return "This browser has no device key for this contract yet. Ask an admin for an enrollment link.";
  if (/only approvers can do this/.test(msg)) return "Your key cannot approve: it is not an approver or admin key.";
  if (/not an eligible approver/.test(msg)) return "This policy names specific approvers, and you are not one of them.";
  if (/already approved/.test(msg)) return "You already approved this request. Another approver must add theirs.";
  if (/attach at least/.test(msg)) return "Not enough gas attached to start signing. Retry.";
  if (/NotEnoughAllowance|allowance/i.test(msg)) return "This key's gas allowance is exhausted. An admin can re-enroll the device.";
  if (/Failed to fetch|NetworkError|RPC HTTP/.test(msg)) return "Could not reach the NEAR RPC endpoint. Nothing was changed.";
  return msg.length > 240 ? msg.slice(0, 240) + "…" : msg;
}
