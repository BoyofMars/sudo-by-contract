# Policy model

Policies read like intent first and JSON second:

> **Deploy Agent may restart checkout-api, payments-api once on production servers after
> one human approval. Access expires after 15m.**

That sentence is generated from the structure below (`policy::describe` in the contract,
`describePolicy` in the client), so the console, CLI and notifications all say the same
thing.

```json
{
  "id": "prod-remediation",
  "name": "Production service remediation",
  "effect": "Allow",
  "subjects":  { "all_agents": false, "agents": ["deploy-agent"] },
  "resources": { "ids": [], "environments": ["production"], "tags": [] },
  "actions":   [{ "kind": "service.restart", "targets": ["checkout-api", "payments-api"] }],
  "max_duration_secs": 900,
  "max_uses": 1,
  "approval":  { "required": 1, "approvers": [] },
  "conditions": { "utc_hours": null, "require_source_address": false }
}
```

| Field | Meaning |
|---|---|
| **Who** `subjects` | Agent ids, or `all_agents` explicitly. |
| **What** `actions` | Typed actions and their targets. `"*"` = any service the resource exposes. |
| **Where** `resources` | Resource ids (`"*"` = any), environments, or tags. Any match selects. |
| **How long** `max_duration_secs` | Upper bound on the window. Requests above it are rejected. |
| **How often** `max_uses` | Executions per capability. `1` = single use. |
| **Approval** `approval` | `required: 0` = policy approves; `n` = n distinct eligible approvers (`approvers` empty = any active approver). Approvers can narrow the window, never widen it. |
| **Conditions** | `utc_hours: [start, end)` request window; `require_source_address` forces the certificate to be bound to the agent's egress CIDR. |
| **Effect** | `Deny` policies match on who × what × where and always win. |

## Evaluation

1. A matching active **Deny** policy rejects the request (`deny` check).
2. Otherwise the request must pass **every** check of at least one active **Allow** policy:
   identity, environment/resource, action, target, duration, uses, schedule, source,
   approval.
3. Among fully matching allow policies, the one needing the **fewest approvals** governs
   (ties: lowest id). Allow policies are grants; their union is what the organisation permits.
4. Before policy is consulted the resource must be **active** and actually **expose** the
   target, and the environment's CA key must exist.
5. The evaluation (`checks[]`), policy id, version and hash are stored with the request:
   the console's "Policy evaluation" panel renders exactly what the contract decided.

`simulate(agent, resource, action, duration, uses)` dry-runs the same function, for the
policy builder's "Test this policy" and for agents' pre-flight checks.

## Typed actions (v1)

| Action | Agent sends over SSH | Gate executes (systemd backend) | Read-only |
|---|---|---|---|
| `service.restart:<unit>` | `sudo systemctl restart <unit>` | `sudo -n /usr/bin/systemctl restart <unit>` | no |
| `service.status:<unit>` | `systemctl status <unit>` | `sudo -n /usr/bin/systemctl status --no-pager <unit>` | yes |
| `logs.read:<unit>` | `journalctl -u <unit> [-n N]` | `sudo -n /usr/bin/journalctl -u <unit> -n {50,100,200,500,1000} --no-pager` | yes |

Unit names match `[A-Za-z0-9][A-Za-z0-9_.@:-]{0,99}` (never a leading `-`, never `/`).
The command line may only contain `[A-Za-z0-9_.@:/=+,-]` and spaces. There is nothing
for a shell to interpret, and nothing is ever given to a shell.

## Templates

| Template | Maps to |
|---|---|
| Service restart | `service.restart` on named services, 1 use, 10–15 min, 1 approval |
| Log inspection | `logs.read` on `*`, up to 10 uses, 15 min, auto |
| Status checks | `service.status` on `*`, 5 uses, 15 min, auto |
| Emergency remediation | `service.restart` on `*`, 1 use, 5 min, 2 approvals |
| Never touch sshd | Deny `service.restart` on `sshd` for all agents |
