# sbc-relay

The relay holds what must stay **off-chain** and pushes events to humans. It is
not in the authorization path: the policy contract and the host gate make every
decision, so if the relay is down, approvals and enforcement still work. You only
lose private context, redacted gate reports and notifications.

```bash
SBC_CONTRACT=sbc.example.testnet \
SBC_CONSOLE_URL=https://console.example.com \
SBC_WEBHOOK_URL=https://hooks.slack.com/services/... \
node apps/relay/src/main.ts
```

| Variable | Default | |
| --- | --- | --- |
| `SBC_CONTRACT` | (required) | Policy contract account id |
| `SBC_RPC` | `https://rpc.testnet.fastnear.com` | NEAR RPC |
| `PORT` | `8787` | |
| `SBC_DB` | `./relay.sqlite` | node:sqlite database |
| `SBC_RETENTION_DAYS` | `30` | Contexts and reports are pruned after this |
| `SBC_WEBHOOK_URL` | (none) | Slack-compatible incoming webhook |
| `SBC_CONSOLE_URL` | (none) | Used for "Review request" deep links |
| `SBC_CORS_ORIGINS` | `*` | Comma-separated origins allowed to call the relay from a browser |
| `SBC_POLL_MS` | `2000` | Contract polling interval for the event stream |

## Authentication

Every call except `/v1/health` is signed by an identity key enrolled on the
contract. These are the same keys that sign transactions:

```
Authorization: SBC-Ed25519 pk=<ed25519:base58>,ts=<unix ms>,sig=<base64>
sig = Ed25519( "sbc-relay/v1\n" + METHOD + "\n" + PATH_AND_QUERY + "\n" + ts + "\n" + sha256hex(body) )
```

`body` is the raw request bytes. When a request has no body, it is the empty
string, so `sha256hex` is `e3b0c442…b855`. The relay rejects timestamps more than
120 s off and replays within 5 minutes. It maps the key to a role with the
contract's `whoami` view (cached 60 s), and fails closed (503) when the chain
cannot be reached.

| Endpoint | Who | |
| --- | --- | --- |
| `GET /v1/health` | anyone | `{ok, contract, rpc, chain_reachable, audit_seq}` |
| `POST /v1/contexts` | Agent | `{rationale, evidence[], links?}` ≤ 16 KB. Stored byte-for-byte; returns `{hash}` = sha256 of the raw body, which the agent records on-chain as `context_hash` |
| `GET /v1/contexts/:hash` | Admin, Approver | The console re-hashes the document and compares it to the on-chain `context_hash` |
| `POST /v1/gate-reports` | Gate (own resource only) | Redacted command, reason code, sha256 of the full command, exit code |
| `GET /v1/gate-reports?request_id=&resource_id=&limit=` | Admin, Approver | |
| `GET /v1/events?auth=<header value>` | Admin, Approver | SSE: `request` (state changes) and `gate_report` events. The header value is signed over `GET /v1/events` |

## Notifications

`Notifier` is a one-method interface (`pendingApproval(notice)`). The relay
calls it exactly once per request that enters `PendingApproval`, and a `notified`
table keeps that true across restarts. Slack-compatible webhooks ship today.
Adding Discord, PagerDuty Events v2, email or Web Push (VAPID) means one class
that formats the notice and makes one HTTP call. Register it in `main.ts`; `FanoutNotifier` isolates failures between channels.

A notification carries only facts that are already public on-chain (agent,
resource, action, window, policy, the agent's short public reason) plus a deep
link. The private context document never leaves the relay.

## Privacy

- Context bodies and commands are never logged.
- Gate reports contain the gate's redacted command line. Credentials are masked
  on the host before upload. The full command exists only as a SHA-256.
- Everything is pruned after `SBC_RETENTION_DAYS`.
