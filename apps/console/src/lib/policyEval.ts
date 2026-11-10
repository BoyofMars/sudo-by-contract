// A faithful TypeScript mirror of contracts/sbc-policy/src/policy.rs.
// Used (1) by the preview simulation and (2) to evaluate an *unsaved draft*
// in the policy builder. The contract's own `simulate` view is the authority
// for anything already on-chain.

import { ACTION_VERBS, formatDuration, splitAction } from "@sbc/client";
import type { Agent, Check, Policy, PolicyInput, Resource } from "@sbc/client";

export interface EvalInput {
  agent: Agent;
  resource: Resource;
  action: string; // canonical
  durationSecs: number;
  uses: number;
  sourceAddress: string | null;
  nowMs: number;
}

export type Outcome = { kind: "auto" } | { kind: "approval"; required: number } | { kind: "rejected" };

export interface EvalResult {
  outcome: Outcome;
  policy: Policy | PolicyInput | null;
  checks: Check[];
}

type P = Policy | PolicyInput;

const active = (p: P) => !("status" in p) || p.status === "Active";

export function subjectMatches(p: P, a: Agent) {
  return p.subjects.all_agents || p.subjects.agents.includes(a.id);
}

export function resourceMatches(p: P, r: Resource) {
  return (
    p.resources.ids.some((i) => i === "*" || i === r.id) ||
    p.resources.environments.includes(r.environment) ||
    p.resources.tags.some((t) => r.tags.includes(t))
  );
}

export function actionMatches(p: P, action: string): [boolean, boolean] {
  const { kind, target } = splitAction(action);
  const kindOk = p.actions.some((r) => r.kind === kind);
  const targetOk = p.actions.some((r) => r.kind === kind && r.targets.some((t) => t === "*" || t === target));
  return [kindOk, targetOk];
}

function inWindow(h: number, [s, e]: [number, number]) {
  if (s === e) return true;
  return s < e ? h >= s && h < e : h >= s || h < e;
}

export function checksFor(p: P, i: EvalInput): Check[] {
  const { kind, target } = splitAction(i.action);
  const out: Check[] = [];
  const c = (name: string, ok: boolean, detail: string) => out.push({ name, ok, detail });
  c("identity", subjectMatches(p, i.agent), p.subjects.all_agents ? `${i.agent.id} (any registered agent)` : i.agent.id);
  c("environment", resourceMatches(p, i.resource), i.resource.environment);
  c("resource", resourceMatches(p, i.resource), i.resource.id);
  const [kindOk, targetOk] = actionMatches(p, i.action);
  c("action", kindOk, ACTION_VERBS[kind]?.verb ?? kind);
  c("target", targetOk, target);
  c("duration", i.durationSecs <= p.max_duration_secs, `requested ${formatDuration(i.durationSecs)} / allowed ${formatDuration(p.max_duration_secs)}`);
  c("uses", i.uses <= p.max_uses, `requested ${i.uses} / allowed ${p.max_uses}`);
  if (p.conditions.utc_hours) {
    const h = Math.floor(i.nowMs / 3_600_000) % 24;
    const [s, e] = p.conditions.utc_hours;
    c("schedule", inWindow(h, p.conditions.utc_hours), `${String(h).padStart(2, "0")}:00 UTC within ${String(s).padStart(2, "0")}:00–${String(e).padStart(2, "0")}:00`);
  }
  if (p.conditions.require_source_address) {
    c("source", !!i.sourceAddress, i.sourceAddress ? `bound to ${i.sourceAddress}` : "certificate must be bound to a source address");
  }
  const n = p.approval.required;
  c("approval", true, n === 0 ? "policy approves automatically" : n === 1 ? "1 human approval required" : `${n} human approvals required`);
  return out;
}

export function evaluate(policies: P[], i: EvalInput): EvalResult {
  for (const p of policies) {
    if (!active(p) || p.effect !== "Deny") continue;
    const [k, t] = actionMatches(p, i.action);
    if (subjectMatches(p, i.agent) && resourceMatches(p, i.resource) && k && t) {
      return { outcome: { kind: "rejected" }, policy: p, checks: [{ name: "deny", ok: false, detail: `explicitly denied by policy “${p.name}”` }] };
    }
  }
  let best: { p: P; cs: Check[] } | null = null;
  let closest: { p: P; cs: Check[]; n: number } | null = null;
  for (const p of policies) {
    if (!active(p) || p.effect !== "Allow") continue;
    const cs = checksFor(p, i);
    const passed = cs.filter((x) => x.ok).length;
    if (passed === cs.length) {
      if (!best || p.approval.required < best.p.approval.required || (p.approval.required === best.p.approval.required && p.id < best.p.id)) best = { p, cs };
    } else if (subjectMatches(p, i.agent) && resourceMatches(p, i.resource) && (!closest || passed > closest.n)) {
      closest = { p, cs, n: passed };
    }
  }
  if (best) {
    const n = best.p.approval.required;
    return { outcome: n === 0 ? { kind: "auto" } : { kind: "approval", required: n }, policy: best.p, checks: best.cs };
  }
  if (closest) return { outcome: { kind: "rejected" }, policy: closest.p, checks: closest.cs };
  return {
    outcome: { kind: "rejected" },
    policy: null,
    checks: [{ name: "identity", ok: false, detail: `no active policy grants ${i.agent.id} anything on ${i.resource.id}` }],
  };
}

/** Client-side mirror of `validate_policy` for inline form errors. */
export function validatePolicy(p: PolicyInput, maxDurationCap = 4 * 3600): string | null {
  const slug = /^[a-z0-9](?:[a-z0-9]|-(?!-)){0,61}[a-z0-9]$/;
  if (!slug.test(p.id)) return "Policy id must be a slug: lowercase letters, digits and single dashes.";
  if (!p.name.trim() || p.name.length > 80) return "Give the policy a name (up to 80 characters).";
  if (p.effect === "Allow" && p.actions.length === 0) return "An allow policy must grant at least one action.";
  for (const r of p.actions) if (!r.targets.length) return "Choose at least one target service (or any).";
  if (!p.subjects.all_agents && p.subjects.agents.length === 0) return "Choose which agents this applies to.";
  if (!p.resources.ids.length && !p.resources.environments.length && !p.resources.tags.length) return "Choose where: environments, resources or tags.";
  if (p.max_duration_secs < 60 || p.max_duration_secs > maxDurationCap) return `Maximum duration must be between 1m and ${formatDuration(maxDurationCap)}.`;
  if (p.max_uses < 1 || p.max_uses > 100) return "Uses must be between 1 and 100.";
  if (p.approval.required > 5) return "At most 5 approvals.";
  if (p.approval.approvers.length && p.approval.required > p.approval.approvers.length) return "More approvals required than eligible approvers.";
  return null;
}
