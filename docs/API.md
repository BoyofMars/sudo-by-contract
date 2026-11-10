# API

Three ways in, one source of truth (the policy contract).

## Agent SDK (`packages/sbc-agent`)

```ts
import { SudoAgent } from "./packages/sbc-agent/src/index.ts";

const sudo = new SudoAgent({
  contractId: "sbc.example.testnet",
  agentSecretKey: process.env.SBC_AGENT_KEY!, // role key enrolled with a one-time token
  relayUrl: "https://relay.example.com",       // optional: private evidence
  stateDir: ".sbc",
});

const cap = await sudo.request({
  resource: "prod-web-02",
  action: "service.restart:checkout-api",
  duration: "10m",
  uses: 1,
  reason: "checkout-api unhealthy after deploy #1842; requesting one restart",
  evidence: [{ label: "error rate", value: "1.2% → 18%" }],
});

await cap.wait({ onState: (s) => console.log(s) }); // PendingApproval → Signing → Active
const out = await cap.exec("sudo systemctl restart checkout-api", { host: "prod-web-02.internal" });
await cap.release();
```

## CLI (`apps/sudoctl`)

```bash
sudoctl request restart checkout-api --on prod-web-02 --for 10m --reason "checkout unhealthy after #1842" --wait
```

```bash
sudoctl exec 42 --host sbc-agent@prod-web-02.internal -- sudo systemctl restart checkout-api
```

```bash
sudoctl approve 42 --for 5m
```

`sudoctl --help` lists setup, agent, approver, inventory and admin commands. Read
commands accept `--json`. Exit codes: 0 ok, 1 error, 2 usage, 3 refused, 4 timeout.

## MCP (`apps/sbc-mcp`)

Tools: `list_resources`, `simulate_access`, `request_capability`, `capability_status`,
`wait_for_capability`, `run_approved_action`, `release_capability`.

## Policy contract

All calls are NEAR function calls on the contract account. Role keys sign *as the
contract account* (they are function-call keys on it); the owner signs as itself.

### Views

| Method | Returns |
|---|---|
| `get_overview()` | config, environments + CA keys, audit seq/head, counts, block time |
| `get_ca(environment)` | `ssh-ed25519 AAAA… sbc-ca:<env>` for `TrustedUserCAKeys` |
| `whoami(public_key)` | the key's role binding, if any |
| `list_agents / list_approvers / list_resources / list_policies (from_index?, limit?)` | entities |
| `get_agent(id) / get_resource(id) / get_policy(id, version?) / describe_policy(id)` | entity / policy sentence |
| `get_request(id)` | request with time-aware state, checks, approvals, certificate, events |
| `list_requests(before_id?, limit?, agent_id?, resource_id?, states?)` | newest first |
| `list_revocations(resource_id)` | revoked serials still inside their window (for KRLs) |
| `simulate(agent_id, resource_id, action, duration_secs, uses?, source_address?)` | dry-run policy evaluation |

### Calls

| Method | Caller | Notes |
|---|---|---|
| `request_access(request)` | Agent | `{resource_id, action, duration_secs, uses?, ssh_public_key, source_address?, reason, context_hash?}`. Auto-approved requests start signing: attach ≥ 150 Tgas. |
| `cancel_request(request_id)` | Agent (own) | release early; issued serial goes to the KRL |
| `approve(request_id, max_duration_secs?)` | Approver / Admin / owner | final approval starts MPC signing: attach ≥ 150 Tgas |
| `deny(request_id, reason)` | Approver / Admin / owner | |
| `revoke(request_id, reason)` | Approver / Admin / owner | any live state |
| `consume(request_id, action, session?)` | Gate (of the capability's resource) | returns `{allowed, code, message, uses, max_uses, valid_before, action}` |
| `report_denial(request_id?, code, program, command_sha256)` | Gate | |
| `heartbeat(gate_version?)` | Gate | |
| `add_environment(name)` | Admin / owner | asks the MPC contract for `derived_public_key` |
| `create_agent / create_approver / create_resource / update_resource` | Admin / owner | |
| `set_agent_status / set_approver_status / set_resource_status` | Admin / owner | resource `Disabled` = kill switch |
| `upsert_policy(policy) / set_policy_status(id, status)` | Admin / owner | versioned + hashed |
| `create_enrollment(role, principal, token_public_key, ttl_secs?)` | Admin / owner | adds a one-shot key allowed only `complete_enrollment` |
| `complete_enrollment(new_public_key, meta?)` | Enrollment token | binds the new key with its role's method list; deletes the token |
| `remove_key(public_key)` | Admin / owner | |
| `set_config(...)` | owner | TTLs, limits, gas, force-command path |
| `on_signed`, `on_ca_key` | private callbacks | |

### Events

NEP-297 logs: `EVENT_JSON:{"standard":"sudo-by-contract","version":"1.0.0","event":…,"data":[…]}`.
Kinds: `request_created`, `policy_evaluated`, `approval_granted`, `approval_denied`,
`approval_expired`, `credential_signing`, `credential_issued`, `credential_failed`,
`credential_discarded`, `command_allowed`, `command_denied`, `authorization_used`,
`authorization_expired`, `authorization_revoked`, `authorization_released`,
`policy_updated`, `policy_status`, `resource_created`, `resource_updated`,
`resource_status`, `agent_created`, `agent_status`, `approver_created`,
`approver_status`, `enrollment_created`, `enrollment_completed`, `enrollment_expired`,
`key_removed`, `environment_created`, `environment_ca_ready`, `environment_ca_failed`,
`config_updated`. Each extends the hash chain `audit_head`.

## Relay

See [apps/relay/README.md](../apps/relay/README.md). Requests are signed:

```
Authorization: SBC-Ed25519 pk=ed25519:<base58>,ts=<unix ms>,sig=<base64>
sig = Ed25519( "sbc-relay/v1\n" METHOD "\n" PATH_AND_QUERY "\n" ts "\n" sha256hex(body) )
```

`sha256hex` of an empty body is the hash of zero bytes (`e3b0c442…b855`).
