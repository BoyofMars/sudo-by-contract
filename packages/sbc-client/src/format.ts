// Human phrasing shared by the console, CLI and notifications, so a policy or
// a capability reads the same everywhere. Mirrors `policy::describe` in Rust.

import type { AccessRequest, Policy, PolicyInput, RequestState } from "./types.ts";

export const ACTION_VERBS: Record<string, { verb: string; title: string; readOnly: boolean; command: (t: string) => string }> = {
  "service.restart": { verb: "restart", title: "Restart", readOnly: false, command: (t) => `sudo systemctl restart ${t}` },
  "service.status": { verb: "read the status of", title: "Read status of", readOnly: true, command: (t) => `systemctl status ${t}` },
  "logs.read": { verb: "read the logs of", title: "Read logs of", readOnly: true, command: (t) => `journalctl -u ${t} -n 100` },
};

export function splitAction(action: string): { kind: string; target: string } {
  const i = action.indexOf(":");
  return i < 0 ? { kind: action, target: "" } : { kind: action.slice(0, i), target: action.slice(i + 1) };
}

/** "Restart checkout-api" */
export function actionTitle(action: string): string {
  const { kind, target } = splitAction(action);
  return `${ACTION_VERBS[kind]?.title ?? kind} ${target}`;
}

/** "sudo systemctl restart checkout-api" — what the agent runs over SSH. */
export function actionCommand(action: string): string {
  const { kind, target } = splitAction(action);
  return ACTION_VERBS[kind]?.command(target) ?? action;
}

export function formatDuration(secs: number): string {
  if (secs >= 3600 && secs % 3600 === 0) return `${secs / 3600}h`;
  if (secs >= 60 && secs % 60 === 0) return `${secs / 60}m`;
  if (secs >= 60) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${secs}s`;
}

/** "07:43" style countdown. */
export function formatCountdown(ms: number): string {
  if (ms <= 0) return "00:00";
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  const mm = String(m).padStart(2, "0");
  const sss = String(ss).padStart(2, "0");
  return h ? `${h}:${mm}:${sss}` : `${mm}:${sss}`;
}

export function describePolicy(p: Policy | PolicyInput, labels: { agent?: (id: string) => string } = {}): string {
  const name = labels.agent ?? ((x: string) => x);
  const who = p.subjects.all_agents ? "Any registered agent" : p.subjects.agents.map(name).join(", ");
  const what = p.actions
    .map((r) => {
      const v = ACTION_VERBS[r.kind]?.verb ?? "act on";
      return r.targets.includes("*") ? `${v} any enrolled service` : `${v} ${r.targets.join(", ")}`;
    })
    .join("; ");
  const where = [
    ...p.resources.ids,
    ...p.resources.environments.map((e) => `${e} servers`),
    ...p.resources.tags.map((t) => `servers tagged ${t}`),
  ].join(", ");
  if (p.effect === "Deny") return `${who} may never ${what} on ${where}.`;
  const uses = p.max_uses === 1 ? "once" : `up to ${p.max_uses} times`;
  const appr =
    p.approval.required === 0
      ? "without human approval"
      : p.approval.required === 1
        ? "after one human approval"
        : `after ${p.approval.required} human approvals`;
  return `${who} may ${what} ${uses} on ${where} ${appr}. Access expires after ${formatDuration(p.max_duration_secs)}.`;
}

export const STATE_LABEL: Record<RequestState, string> = {
  PendingApproval: "Awaiting approval",
  Signing: "Issuing credential",
  Active: "Active",
  Exhausted: "Used",
  Expired: "Expired",
  Revoked: "Revoked",
  Denied: "Denied",
  Rejected: "Rejected by policy",
  ApprovalExpired: "Approval timed out",
  Failed: "Issuance failed",
  Cancelled: "Released",
};

export type Tone = "neutral" | "pending" | "active" | "success" | "danger" | "muted";

export const STATE_TONE: Record<RequestState, Tone> = {
  PendingApproval: "pending",
  Signing: "pending",
  Active: "active",
  Exhausted: "success",
  Expired: "muted",
  Revoked: "danger",
  Denied: "danger",
  Rejected: "danger",
  ApprovalExpired: "muted",
  Failed: "danger",
  Cancelled: "muted",
};

/** Milliseconds of authority left, using the chain's clock offset if known. */
export function remainingMs(r: AccessRequest, nowMs = Date.now()): number {
  return r.state === "Active" ? Math.max(0, r.valid_before * 1000 - nowMs) : 0;
}

/** Coarse blast-radius label shown on approval screens. */
export function riskOf(r: Pick<AccessRequest, "action" | "environment" | "granted_duration_secs" | "requested_duration_secs" | "max_uses">): { level: "low" | "limited" | "elevated"; why: string } {
  const { kind } = splitAction(r.action);
  const readOnly = ACTION_VERBS[kind]?.readOnly ?? false;
  const prod = /prod/.test(r.environment);
  const dur = r.granted_duration_secs || r.requested_duration_secs;
  if (readOnly) return { level: "low", why: "read-only action" };
  if (prod && (r.max_uses > 3 || dur > 3600)) return { level: "elevated", why: "repeated mutating access on production" };
  if (prod) return { level: "limited", why: `one mutating action on production, ${r.max_uses === 1 ? "single use" : `${r.max_uses} uses`}, no shell` };
  return { level: "low", why: "non-production, no shell" };
}
