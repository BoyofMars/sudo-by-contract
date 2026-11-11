# Sudo by Contract — console design system

The console is security software. Its job is to make one thing obvious at a
glance: **everything dangerous has boundaries**. It should feel controlled,
precise, calm, technical and fast — closer to Linear, Tailscale or Sentry than
to anything that looks like a crypto dashboard. NEAR stays under "Technical
proof"; the interface speaks policy, access, agents, servers and audit.

## Principles

1. **Consequence first.** Every decision screen states, in one sentence, what
   approving means ("Approving lets Deploy Agent restart checkout-api on
   prod-web-02 once, within a 10m window… No shell, no other command, no other
   host."). Nobody decodes JSON to approve production access.
2. **Policy reads like intent.** Policies are rendered as sentences
   (`describePolicy`, mirrored from the contract's `policy::describe`). The
   structure is one disclosure away ("Advanced").
3. **Denials are first-class.** A blocked `sudo cat /etc/shadow` is shown with
   the same weight as a success: who, what they attempted, and why it was
   refused. It is the product working.
4. **Time is visible where it matters, calm elsewhere.** Countdowns appear on
   active capabilities and request detail only, in mono, without color
   escalation or animation beyond a 1 s hairline move.
5. **Every async step explains the technology.** No generic spinners:
   "Approval recorded on NEAR → Policy satisfied → Threshold signature from
   NEAR MPC → SSH certificate issued → Capability active on the host".
6. **Honesty over polish.** Preview data is labeled on every screen. Context
   from the relay shows whether it matches the on-chain hash. Failures say
   "nothing was issued".

## Motif: bounded windows

Privilege exists inside a window. The mark is a privilege bar held between two
brackets. The same idea drives the **WindowBar** component: a faint tick track
(time), a bracketed span (the window), hatching for elapsed time, and a single
hairline for "now". Pending requests show a dashed amber window ("starts when
the certificate is issued"). Closed capabilities turn gray. No padlocks.

## Tokens (`src/styles/tokens.css`)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` / `--surface` / `--surface-2/3` | #fafaf9 / #fff / … | #0b0c0e / #111215 / … | page, panels, wells |
| `--line` / `--line-strong` | #e6e5e1 / #d4d3cd | #23252b / #30333a | hairlines, inputs |
| `--text` / `-2` / `-3` | #16171a / #53555c / #8a8c93 | #ececee / #a3a6ae / #6d7079 | primary, secondary, tertiary |
| `--ink` | text color | text color | primary buttons, selected chips |
| `--active` (+ `-bg`, `-line`) | #0a8572 | #3cc9b0 | live authority, allowed, approve |
| `--pending` | #9a6208 | #eeb54f | awaiting approval, signing |
| `--danger` | #be3029 | #f2756d | denied, revoked, rejected |
| `--muted` | #6f7178 | #8e919a | expired, released, closed |

Color is semantic only. There is exactly one accent hue (the active teal); the
brand otherwise lives in typography and layout. Dark theme follows
`prefers-color-scheme`, overridable with the theme toggle (`data-theme` on
`<html>`, persisted in `localStorage`).

**Type.** Inter (UI) and JetBrains Mono (identifiers, commands, hashes, time),
both self-hosted via `@fontsource-variable`. Scale: 11 / 12 / 13 / 14 / 15 /
17 / 20 / 24 / 32 / 44 / 56 px. Body 14 px; dense tables 13 px; labels 11 px
uppercase with 0.06–0.07 em tracking. Headings use −0.012 to −0.035 em.

**Space.** 4 px grid (`--s-1`…`--s-24`). Radii are small: 4 / 6 / 8 px.
Shadows only for popovers and dialogs.

**Widths.** Page 1180 px, narrow flows 760 px, sidebar 232 px, top bar 48 px.

## Components

All in `src/components`:

- **Buttons** — `primary` (ink), `secondary` (outlined), `ghost`, `approve`
  (the only green button in the product), `danger` (outlined red). Sizes `xs`,
  default, `lg`; `btn-icon`.
- **Inputs** — `input`, `select`, `textarea`, `Field` (label + hint/error),
  `Chips` (multi-select), `Segmented`.
- **Badge / StateBadge** — dot + label, tone from `STATE_TONE`.
- **Command** — dark terminal block for exact commands, with copy.
- **KV / facts** — definition lists for "WHO / WHAT / WHERE / WINDOW / USES /
  POLICY / RISK".
- **PolicyChecks** — ✓ / ✕ / ○ rows from the contract's `checks`, with the
  approval row derived from live state (○ waiting → ✓ approved by…).
- **Timeline** — human titles, mono timestamps, tap to expand the raw event
  (kind, seq, actor, detail).
- **WindowBar** — see motif.
- **Panel, PageHeader, Empty, Skeleton, Dialog** (native `<dialog>`, becomes a
  bottom sheet under 640 px), **Toasts**, **Truncate** for keys/hashes.
- **HeroTerminal** — scripted landing visualization; pauses off-screen,
  respects `prefers-reduced-motion` (renders the final state statically).

## Layout & responsive rules

- ≥ 821 px: left sidebar + sticky top bar (connection, audit seq, identity).
- ≤ 820 px: sidebar becomes a bottom tab bar (Overview, Requests, Active,
  Audit, More → sheet). Pending count badges the Requests tab.
- ≤ 640 px on request detail: a fixed, thumb-reachable action bar (Deny |
  Approve 10m, or Revoke now) sits above the tab bar; dialogs become bottom
  sheets with 44 px buttons; fact rows stack; no horizontal scroll (verified at
  375 px).
- Tables scroll horizontally inside their frame; secondary columns hide under
  900 px (`hide-md`).

## Data layer

Pages talk to one `DataSource` interface (`src/lib/data/source.ts`):

- **LiveSource** — `SudoContract` views over NEAR RPC; writes signed by the
  browser's **device key**; private context and gate reports from the relay.
- **PreviewSource** — an in-memory simulation of the same state machine used
  when no contract is configured. It evaluates requests with a TypeScript
  mirror of the contract's policy logic (`src/lib/policyEval.ts`) and issues
  structurally real OpenSSH certificates signed by a throwaway in-browser key.
  Every preview surface carries the "Simulation" banner with a way back to the
  live contract.

Config resolution: `?contract=&rpc=&relay=` (query or hash query) →
`localStorage` → `VITE_SBC_CONTRACT` / `VITE_SBC_RPC` / `VITE_SBC_RELAY`. The
hosted build sets `VITE_SBC_CONTRACT`, so visitors land on the live contract
(read-only, under a "Live" strip that also hides `e2e-*` test fixtures behind a
toggle). `?preview=1` switches to the simulation for the rest of the tab
session; `?preview=0` or any `?contract=` switches back.

### Device keys (how humans authenticate)

`#/join?contract=…&token=…` generates a **non-extractable** WebCrypto Ed25519
key pair, stores the `CryptoKeyPair` in IndexedDB (structured clone keeps it
non-extractable), and signs `complete_enrollment(new_public_key)` with the
one-time token. On-chain the device key is a function-call access key on the
contract account restricted to its role's methods (approvers: `approve`,
`deny`, `revoke`). No wallet, no seed phrase, nothing to export.

### Relay requests

`Authorization: SBC-Ed25519 pk=<ed25519:base58>,ts=<ms>,sig=<base64>`, where
the signature covers `sbc-relay/v1\n{METHOD}\n{PATH_AND_QUERY}\n{ts}\n{sha256hex(body)}`
(for GET the body is empty, i.e. `sha256("")`). The SSE stream passes the same
header value as `?auth=` signed over the path `/v1/events`. Context documents
are verified client-side against the on-chain `context_hash`
(`sha256(raw)` if the relay returns `raw`, else `sha256(JSON.stringify(document))`).

## Notifications

- **Now:** with the console open, relay SSE events trigger an immediate
  refetch; Settings offers browser notification permission.
- **Designed hook:** `public/sw.js` handles `push` (`{title, body, url}`) and
  `notificationclick` (focuses or opens the deep link
  `#/console/requests/:id`). The relay is the natural Web Push (VAPID) sender
  alongside Slack/webhook approval cards; subscriptions would be registered
  with a signed relay request. Server-side push is not implemented.

## PWA

`manifest.webmanifest` (standalone, SVG + maskable icons, shortcuts to pending
approvals and active access) and a service worker that caches only the app
shell and hashed assets. RPC and relay responses are never cached: a stale
"Active" would be a lie.
