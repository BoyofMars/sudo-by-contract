// JSON shapes of the policy contract (contracts/sbc-policy/src/types.rs).
// Keep in sync: field names are snake_case exactly as serialized by near-sdk.

export type Role = "Admin" | "Approver" | "Agent" | "Gate" | "Enrollment";
export type Status = "Active" | "Suspended";
export type ResourceStatus = "Pending" | "Active" | "Disabled";
export type Effect = "Allow" | "Deny";
export type ActionKind = "service.restart" | "service.status" | "logs.read";

export type RequestState =
  | "PendingApproval"
  | "Signing"
  | "Active"
  | "Exhausted"
  | "Expired"
  | "Revoked"
  | "Denied"
  | "Rejected"
  | "ApprovalExpired"
  | "Failed"
  | "Cancelled";

export const LIVE_STATES: RequestState[] = ["PendingApproval", "Signing", "Active"];

export interface KeyBinding {
  role: Role;
  principal: string;
  added_at_ms: number;
  enrolls_as: Role | null;
  expires_at_ms: number | null;
}

export interface AgentStats {
  requests: number;
  auto_approved: number;
  approved: number;
  denied: number;
  rejected: number;
  revoked: number;
  actions_allowed: number;
  actions_denied: number;
}

export interface Agent {
  id: string;
  label: string;
  owner: string;
  runtime: string;
  keys: string[];
  status: Status;
  created_at_ms: number;
  stats: AgentStats;
}

export interface Approver {
  id: string;
  label: string;
  is_admin: boolean;
  keys: string[];
  status: Status;
  created_at_ms: number;
}

export interface Resource {
  id: string;
  label: string;
  environment: string;
  tags: string[];
  services: string[];
  principal: string;
  gate_key: string | null;
  gate_version: string | null;
  host_fingerprint: string | null;
  status: ResourceStatus;
  created_at_ms: number;
  enrolled_at_ms: number | null;
  last_seen_ms: number | null;
}

export interface ActionRule {
  kind: ActionKind | string;
  targets: string[];
}

export interface PolicyInput {
  id: string;
  name: string;
  description: string;
  effect: Effect;
  subjects: { all_agents: boolean; agents: string[] };
  resources: { ids: string[]; environments: string[]; tags: string[] };
  actions: ActionRule[];
  max_duration_secs: number;
  max_uses: number;
  approval: { required: number; approvers: string[] };
  conditions: { utc_hours: [number, number] | null; require_source_address: boolean };
}

export interface Policy extends PolicyInput {
  version: number;
  status: Status;
  updated_at_ms: number;
  updated_by: string;
  hash: string;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

export interface Approval {
  approver_id: string;
  at_ms: number;
  max_duration_secs: number | null;
}

export interface RequestEvent {
  seq: number;
  at_ms: number;
  kind: string;
  actor: string;
  detail: string;
}

export interface AccessRequest {
  id: number;
  agent_id: string;
  resource_id: string;
  environment: string;
  action: string;
  requested_duration_secs: number;
  requested_uses: number;
  ssh_public_key: string;
  source_address: string | null;
  reason: string;
  context_hash: string | null;
  created_at_ms: number;
  approval_deadline_ms: number;
  policy_id: string | null;
  policy_version: number | null;
  policy_hash: string | null;
  checks: Check[];
  required_approvals: number;
  eligible_approvers: string[];
  approvals: Approval[];
  state: RequestState;
  state_reason: string | null;
  granted_duration_secs: number;
  max_uses: number;
  uses: number;
  denied_attempts: number;
  valid_after: number;
  valid_before: number;
  pending_tbs: string | null;
  certificate: string | null;
  signed_at_ms: number | null;
  revoked_by: string | null;
  events: RequestEvent[];
}

export interface RequestAccessArgs {
  resource_id: string;
  action: string;
  duration_secs: number;
  uses?: number | null;
  ssh_public_key: string;
  source_address?: string | null;
  reason: string;
  context_hash?: string | null;
}

export interface Environment {
  name: string;
  path: string;
  ca_public_key: string | null;
  ca_public_key_ssh: string | null;
  created_at_ms: number;
}

export interface Revocation {
  serial: number;
  resource_id: string;
  at_ms: number;
  valid_before: number;
}

export interface Config {
  owner: string;
  mpc_contract: string;
  mpc_domain_id: number;
  ca_version: number;
  force_command: string;
  skew_secs: number;
  approval_ttl_secs: number;
  max_pending_per_agent: number;
  max_duration_secs: number;
  allowance_admin: string;
  allowance_approver: string;
  allowance_agent: string;
  allowance_gate: string;
  allowance_enrollment: string;
  sign_gas_tgas: number;
  callback_gas_tgas: number;
  /** Distinct admins required for a policy change (1 = any admin alone). */
  policy_quorum: number;
}

export interface PolicyProposal {
  id: number;
  policy: PolicyInput;
  proposer: string;
  approvals: string[];
  created_at_ms: number;
  expires_at_ms: number;
}

export interface Overview {
  config: Config;
  environments: Environment[];
  audit_seq: number;
  audit_head: string;
  request_count: number;
  agent_count: number;
  resource_count: number;
  policy_count: number;
  approver_count: number;
  revocation_count: number;
  now_ms: number;
}

export interface ConsumeResult {
  allowed: boolean;
  code: string;
  message: string;
  uses: number;
  max_uses: number;
  valid_before: number;
  action: string;
}

export interface SimulateResult {
  outcome: "auto_approved" | "needs_approval" | "rejected";
  policy_id: string | null;
  policy_name: string | null;
  required_approvals: number;
  checks: Check[];
}

export interface EnrollResult {
  ok: boolean;
  role: Role | null;
  principal: string;
  message: string;
}

/** NEP-297 event emitted by the contract (`EVENT_JSON:` log lines). */
export interface ContractEvent {
  standard: "sudo-by-contract";
  version: string;
  event: string;
  data: Array<Record<string, unknown> & { seq: number; at_ms: number; actor: string }>;
}
