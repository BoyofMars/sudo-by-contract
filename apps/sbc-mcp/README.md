# sbc-mcp: Sudo by Contract for AI agents

An MCP server (stdio) that lets an AI agent such as Claude Code or Claude Desktop
ask for **one narrowly scoped, temporary capability** and use it. The agent never
holds a reusable credential:

1. `request_capability` generates a fresh Ed25519 key on this machine and records
   the request on the policy contract. The private context goes to the relay and
   only its hash goes on-chain.
2. Policy decides. If policy requires it, a human approves in the console (or
   with `sudoctl approve`).
3. `wait_for_capability` returns when the NEAR MPC network has signed a short-lived
   SSH certificate. The certificate is bound to that key, that host and that
   window, and forced through the host gate.
4. `run_approved_action` runs exactly the approved action. The host gate refuses
   anything else and records the refusal.
5. `release_capability` gives the authority back.

| Tool | What it does |
| --- | --- |
| `list_resources` | Enrolled servers and the services they expose |
| `simulate_access` | Dry-run against current policy (which checks pass or fail) |
| `request_capability` | Submit a request; returns immediately with the policy outcome |
| `capability_status` | Pending / issuing / active (time and uses left) / finished |
| `wait_for_capability` | Block until usable or ended (a human may need to approve) |
| `run_approved_action` | Run one command via SSH under the capability; refusals come back verbatim |
| `release_capability` | Revoke your own certificate serial now |

## Add to Claude Code

First enroll an agent key once (`sudoctl init --contract … && sudoctl enroll --token …`), then:

```bash
claude mcp add sudo-by-contract \
  -e SBC_CONTRACT=sbc.example.testnet \
  -e SBC_AGENT_KEY_FILE=$HOME/.sbc/keys/agent-deploy-agent.json \
  -e SBC_RELAY=https://relay.example.com \
  -e SBC_CONSOLE_URL=https://console.example.com \
  -e 'SBC_HOSTS={"prod-web-02":"sbc-agent@10.0.4.12:22"}' \
  -- node /path/to/sudo-by-contract/apps/sbc-mcp/src/main.ts
```

Environment variables:

| Variable | Meaning |
| --- | --- |
| `SBC_CONTRACT` | Policy contract account id (required) |
| `SBC_AGENT_KEY` / `SBC_AGENT_KEY_FILE` | The agent's enrolled access key (`ed25519:…`, or a `sudoctl` key file) |
| `SBC_RPC` | NEAR RPC (default `https://rpc.testnet.fastnear.com`) |
| `SBC_RELAY` | Relay that holds private context documents (optional) |
| `SBC_HOSTS` | JSON map of resource id to `user@host:port`. Kept off-chain on purpose |
| `SBC_CONSOLE_URL` | Lets the server hand approvers a review link |
| `SBC_STATE_DIR` | Where ephemeral keys and certificates live (default `~/.sbc/mcp`) |

Requires Node ≥ 24 and the OpenSSH client (`ssh`) on PATH. There are no npm dependencies.
