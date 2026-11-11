// Human phrasing for contract events, and helpers to treat denials as
// first-class records.

import { actionCommand, type AccessRequest, type RequestEvent } from "@sbc/client";
import type { GateReport } from "./relay.ts";

export const EVENT_KINDS = [
  "request_created",
  "policy_evaluated",
  "approval_granted",
  "approval_denied",
  "approval_expired",
  "credential_signing",
  "credential_issued",
  "credential_failed",
  "credential_discarded",
  "command_allowed",
  "command_denied",
  "authorization_used",
  "authorization_expired",
  "authorization_revoked",
  "authorization_released",
] as const;

/** Filter groups for people; the raw kind stays in the expanded detail. */
export const EVENT_GROUPS: { value: string; label: string; short: string; kinds: string[] }[] = [
  { value: "requests", label: "Requests", short: "request", kinds: ["request_created", "policy_evaluated"] },
  { value: "approvals", label: "Approvals", short: "approval", kinds: ["approval_granted", "approval_denied", "approval_expired"] },
  { value: "certificates", label: "Certificates", short: "certificate", kinds: ["credential_signing", "credential_issued", "credential_failed", "credential_discarded"] },
  { value: "commands", label: "Commands", short: "command", kinds: ["command_allowed", "command_denied", "authorization_used"] },
  { value: "endings", label: "Expiry & revocation", short: "end", kinds: ["authorization_expired", "authorization_revoked", "authorization_released"] },
  { value: "denials", label: "Denials only", short: "denial", kinds: ["command_denied", "approval_denied", "credential_failed"] },
];

export function groupOf(kind: string): string {
  return EVENT_GROUPS.find((g) => g.value !== "denials" && g.kinds.includes(kind))?.short ?? "event";
}

export type EventTone = "neutral" | "active" | "pending" | "danger" | "success" | "muted";

export function eventTitle(e: RequestEvent, label: (id: string) => string = (x) => x): { title: string; tone: EventTone } {
  const who = e.actor.startsWith("owner:") ? "owner" : label(e.actor);
  switch (e.kind) {
    case "request_created": return { title: `Requested by ${who}`, tone: "neutral" };
    case "policy_evaluated": return { title: "Policy evaluated", tone: /rejected|:|does not|no active/.test(e.detail) && !/requires|auto-approved/.test(e.detail) ? "danger" : "neutral" };
    case "approval_granted": return e.actor === "policy" ? { title: "Approved by policy", tone: "success" } : { title: `Approved by ${who}`, tone: "success" };
    case "approval_denied": return { title: `Denied by ${who}`, tone: "danger" };
    case "approval_expired": return { title: "Approval window elapsed", tone: "muted" };
    case "credential_signing": return { title: "Threshold signature requested from NEAR MPC", tone: "neutral" };
    case "credential_issued": return { title: "SSH certificate issued", tone: "active" };
    case "credential_failed": return { title: "Issuance failed — nothing was issued", tone: "danger" };
    case "credential_discarded": return { title: "Late signature discarded", tone: "muted" };
    case "command_allowed": return { title: "Command allowed on host", tone: "success" };
    case "command_denied": return { title: "Command denied on host", tone: "danger" };
    case "authorization_used": return { title: "Capability used up", tone: "muted" };
    case "authorization_expired": return { title: "Authorization expired", tone: "muted" };
    case "authorization_revoked": return { title: `Revoked by ${who}`, tone: "danger" };
    case "authorization_released": return { title: "Released by agent", tone: "muted" };
    default: return { title: e.kind.replace(/_/g, " "), tone: "neutral" };
  }
}

export interface Denial {
  request: AccessRequest;
  event: RequestEvent;
  code: string;
  /** What the agent tried, as a command line. */
  attempted: string;
  /** Why it was refused, phrased for humans. */
  why: string;
}

export const CODE_WHY: Record<string, string> = {
  no_adapter: "not an action Sudo by Contract can authorize",
  shell_metacharacter: "shell metacharacters are never accepted",
  interactive_session: "interactive shells are never granted",
  unsupported_sudo_flag: "sudo flags like -u/-s/-i are not supported",
  unsupported_arguments: "this form of the command is not an authorizable action",
  invalid_target: "not a valid service name",
  expired: "authorization expired",
  revoked: "authorization was revoked",
  exhausted: "all permitted uses are consumed",
  released: "the agent already released this capability",
  wrong_resource: "capability is bound to a different host",
  resource_disabled: "this resource is disabled",
  not_active: "capability is not active",
};

/** Parse a `command_denied` event detail written by the contract. */
export function parseDenial(r: AccessRequest, e: RequestEvent, reports: GateReport[] = []): Denial {
  const m = /^([a-z_]+): attempted (.+?)(?: \((.*)\))?(?: session=.*)?$/.exec(e.detail);
  const code = m?.[1] ?? "denied";
  let attemptedRaw = (m?.[2] ?? e.detail).trim();
  let attempted: string;
  const prog = /^`([^`]+)`/.exec(attemptedRaw);
  if (prog) {
    // local gate rejection: only the program is on-chain; the relay has the redacted text
    const rep = reports.find((x) => x.request_id === r.id && x.decision === "denied" && x.program === prog[1] && Math.abs(x.at_ms - e.at_ms) < 120_000);
    attempted = rep?.redacted_command ?? `${prog[1]} …`;
  } else {
    attemptedRaw = attemptedRaw.replace(/ sha256=.*$/, "");
    const rep = reports.find((x) => x.request_id === r.id && x.decision === "denied" && x.action === attemptedRaw && Math.abs(x.at_ms - e.at_ms) < 120_000);
    attempted = rep?.redacted_command ?? (attemptedRaw.includes(":") ? actionCommand(attemptedRaw) : attemptedRaw);
  }
  const why = code === "out_of_scope" ? `capability permits only ${r.action}` : CODE_WHY[code] ?? m?.[3] ?? code.replace(/_/g, " ");
  return { request: r, event: e, code, attempted, why };
}

export function denialsOf(requests: AccessRequest[], reports: GateReport[] = []): Denial[] {
  const out: Denial[] = [];
  for (const r of requests) for (const e of r.events) if (e.kind === "command_denied") out.push(parseDenial(r, e, reports));
  return out.sort((a, b) => b.event.at_ms - a.event.at_ms);
}

export function timeAgo(ms: number, now = Date.now()): string {
  const d = Math.max(0, now - ms);
  if (d < 45_000) return "just now";
  if (d < 3_600_000) return `${Math.round(d / 60_000)}m ago`;
  if (d < 86_400_000) return `${Math.round(d / 3_600_000)}h ago`;
  return `${Math.round(d / 86_400_000)}d ago`;
}

// Times are shown in UTC, labelled, everywhere: certificates, the proof page
// and CI logs are UTC, and judges read them side by side.
export function clock(ms: number): string {
  return `${new Date(ms).toLocaleTimeString("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit" })} UTC`;
}

export function dateTime(ms: number): string {
  return `${new Date(ms).toLocaleString("en-US", { timeZone: "UTC", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" })} UTC`;
}
