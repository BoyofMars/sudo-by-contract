//! Policy evaluation. Pure functions over plain data so they can be tested
//! exhaustively and exposed as a dry-run view (`simulate`).
//!
//! Semantics, in the order an operator should read them:
//!
//! 1. Any matching **deny** policy rejects the request. Deny always wins.
//! 2. Otherwise the request must satisfy *every* check of at least one active
//!    **allow** policy. Nothing is allowed by default.
//! 3. If several allow policies fully match, the one requiring the fewest
//!    human approvals governs (ties: lowest policy id). Allow policies are
//!    grants; the union of grants is what the organisation has permitted.
//! 4. Requests that ask for more than a policy allows (e.g. 30 minutes when
//!    the policy says 15) are rejected, not silently clamped, so the agent
//!    and the approver both see exactly what was granted.

use crate::types::*;
use sbc_core::action::{Action, ActionKind};

pub struct EvalInput<'a> {
    pub agent: &'a Agent,
    pub resource: &'a Resource,
    pub action: &'a Action,
    pub duration_secs: u32,
    pub uses: u32,
    pub source_address: Option<&'a str>,
    pub now_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    AutoApproved,
    NeedsApproval(u8),
    Rejected,
}

#[derive(Clone, Debug)]
pub struct EvalResult {
    pub outcome: Outcome,
    pub policy: Option<Policy>,
    pub checks: Vec<Check>,
}

fn check(name: &str, ok: bool, detail: String) -> Check {
    Check { name: name.to_string(), ok, detail }
}

fn fmt_dur(secs: u32) -> String {
    if secs % 3600 == 0 && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

pub fn subject_matches(p: &Policy, agent: &Agent) -> bool {
    p.subjects.all_agents || p.subjects.agents.iter().any(|a| a == &agent.id)
}

pub fn resource_matches(p: &Policy, r: &Resource) -> bool {
    p.resources.ids.iter().any(|i| i == "*" || i == &r.id)
        || p.resources.environments.iter().any(|e| e == &r.environment)
        || p.resources.tags.iter().any(|t| r.tags.contains(t))
}

pub fn action_matches(p: &Policy, a: &Action) -> (bool, bool) {
    let kind_ok = p.actions.iter().any(|r| r.kind == a.kind.as_str());
    let target_ok = p
        .actions
        .iter()
        .any(|r| r.kind == a.kind.as_str() && r.targets.iter().any(|t| t == "*" || t == &a.target));
    (kind_ok, target_ok)
}

fn hour_utc(now_ms: u64) -> u8 {
    ((now_ms / 1000 / 3600) % 24) as u8
}

fn in_window(h: u8, w: [u8; 2]) -> bool {
    let [s, e] = w;
    if s == e {
        true
    } else if s < e {
        h >= s && h < e
    } else {
        // wraps midnight, e.g. [22, 6)
        h >= s || h < e
    }
}

/// All checks of one allow policy against the input.
pub fn checks_for(p: &Policy, i: &EvalInput) -> Vec<Check> {
    let mut out = Vec::with_capacity(9);
    out.push(check(
        "identity",
        subject_matches(p, i.agent),
        if p.subjects.all_agents {
            format!("{} (any registered agent)", i.agent.id)
        } else {
            i.agent.id.clone()
        },
    ));
    out.push(check("environment", resource_matches(p, i.resource), i.resource.environment.clone()));
    out.push(check("resource", resource_matches(p, i.resource), i.resource.id.clone()));
    let (kind_ok, target_ok) = action_matches(p, i.action);
    out.push(check("action", kind_ok, i.action.kind.verb().to_string()));
    out.push(check("target", target_ok, i.action.target.clone()));
    out.push(check(
        "duration",
        i.duration_secs <= p.max_duration_secs,
        format!("requested {} / allowed {}", fmt_dur(i.duration_secs), fmt_dur(p.max_duration_secs)),
    ));
    out.push(check(
        "uses",
        i.uses <= p.max_uses,
        format!("requested {} / allowed {}", i.uses, p.max_uses),
    ));
    if let Some(w) = p.conditions.utc_hours {
        let h = hour_utc(i.now_ms);
        out.push(check(
            "schedule",
            in_window(h, w),
            format!("{:02}:00 UTC within {:02}:00–{:02}:00", h, w[0], w[1]),
        ));
    }
    if p.conditions.require_source_address {
        out.push(check(
            "source",
            i.source_address.is_some(),
            i.source_address.map(|s| format!("bound to {}", s)).unwrap_or_else(|| "certificate must be bound to a source address".into()),
        ));
    }
    out.push(check(
        "approval",
        true,
        match p.approval.required {
            0 => "policy approves automatically".into(),
            1 => "1 human approval required".into(),
            n => format!("{} human approvals required", n),
        },
    ));
    out
}

pub fn evaluate(policies: &[&Policy], i: &EvalInput) -> EvalResult {
    // 1. explicit deny wins
    for p in policies.iter().copied() {
        if p.status != Status::Active || p.effect != Effect::Deny {
            continue;
        }
        let (kind_ok, target_ok) = action_matches(p, i.action);
        if subject_matches(p, i.agent) && resource_matches(p, i.resource) && kind_ok && target_ok {
            return EvalResult {
                outcome: Outcome::Rejected,
                policy: Some(p.clone()),
                checks: vec![check("deny", false, format!("explicitly denied by policy \u{201c}{}\u{201d}", p.name))],
            };
        }
    }

    // 2. find fully-matching allow policies
    let mut best: Option<(&Policy, Vec<Check>)> = None;
    let mut closest: Option<(&Policy, Vec<Check>, usize)> = None;
    for p in policies.iter().copied() {
        if p.status != Status::Active || p.effect != Effect::Allow {
            continue;
        }
        let cs = checks_for(p, i);
        let passed = cs.iter().filter(|c| c.ok).count();
        if passed == cs.len() {
            let better = match &best {
                None => true,
                Some((b, _)) => {
                    p.approval.required < b.approval.required
                        || (p.approval.required == b.approval.required && p.id < b.id)
                }
            };
            if better {
                best = Some((p, cs));
            }
        } else {
            // only explain with policies that are at least about this agent and resource
            let relevant = subject_matches(p, i.agent) && resource_matches(p, i.resource);
            if relevant && closest.as_ref().map(|(_, _, n)| passed > *n).unwrap_or(true) {
                closest = Some((p, cs, passed));
            }
        }
    }

    match (best, closest) {
        (Some((p, cs)), _) => EvalResult {
            outcome: if p.approval.required == 0 {
                Outcome::AutoApproved
            } else {
                Outcome::NeedsApproval(p.approval.required)
            },
            policy: Some(p.clone()),
            checks: cs,
        },
        (None, Some((p, cs, _))) => EvalResult { outcome: Outcome::Rejected, policy: Some(p.clone()), checks: cs },
        (None, None) => EvalResult {
            outcome: Outcome::Rejected,
            policy: None,
            checks: vec![check(
                "identity",
                false,
                format!("no active policy grants {} anything on {}", i.agent.id, i.resource.id),
            )],
        },
    }
}

/// Validate a policy submitted by an admin. Returns a human-readable error.
pub fn validate_policy(p: &PolicyInput, max_duration_cap: u32) -> Result<(), String> {
    if !sbc_core::validate::is_slug(&p.id) {
        return Err("policy id must be a slug (a-z, 0-9, -)".into());
    }
    if !sbc_core::validate::is_label(&p.name) {
        return Err("policy name must be 1-80 printable characters".into());
    }
    if p.description.len() > 500 {
        return Err("description is limited to 500 characters".into());
    }
    if p.effect == Effect::Allow && p.actions.is_empty() {
        return Err("an allow policy must grant at least one action".into());
    }
    if p.actions.len() > 16 {
        return Err("at most 16 action rules per policy".into());
    }
    for r in &p.actions {
        if ActionKind::parse(&r.kind).is_none() {
            return Err(format!("unknown action kind {}", r.kind));
        }
        if r.targets.is_empty() || r.targets.len() > 32 {
            return Err("each action rule needs 1-32 targets".into());
        }
        for t in &r.targets {
            if t != "*" && !sbc_core::validate::is_unit_name(t) {
                return Err(format!("invalid target {}", t));
            }
        }
    }
    if !p.subjects.all_agents && p.subjects.agents.is_empty() {
        return Err("policy must name its subjects (or explicitly select all agents)".into());
    }
    if p.resources.ids.is_empty() && p.resources.environments.is_empty() && p.resources.tags.is_empty() {
        return Err("policy must select resources by id, environment or tag".into());
    }
    let n = p.subjects.agents.len() + p.resources.ids.len() + p.resources.environments.len() + p.resources.tags.len();
    if n > 64 || p.approval.approvers.len() > 16 {
        return Err("selector lists are too long".into());
    }
    if p.max_duration_secs < 60 || p.max_duration_secs > max_duration_cap {
        return Err(format!("max duration must be between 1 minute and {}", fmt_dur(max_duration_cap)));
    }
    if p.max_uses == 0 || p.max_uses > 100 {
        return Err("max uses must be between 1 and 100".into());
    }
    if p.approval.required > 5 {
        return Err("at most 5 approvals".into());
    }
    if !p.approval.approvers.is_empty() && (p.approval.required as usize) > p.approval.approvers.len() {
        return Err("more approvals required than eligible approvers".into());
    }
    if let Some([s, e]) = p.conditions.utc_hours {
        if s > 23 || e > 24 {
            return Err("utc_hours must be within 0-24".into());
        }
    }
    Ok(())
}

/// One-sentence rendering of a policy, mirroring the console's wording.
pub fn describe(p: &Policy) -> String {
    let who = if p.subjects.all_agents { "Any registered agent".to_string() } else { p.subjects.agents.join(", ") };
    let what: Vec<String> = p
        .actions
        .iter()
        .map(|r| {
            let k = ActionKind::parse(&r.kind).map(|k| k.verb()).unwrap_or("act on");
            if r.targets.iter().any(|t| t == "*") {
                format!("{} any enrolled service", k)
            } else {
                format!("{} {}", k, r.targets.join(", "))
            }
        })
        .collect();
    let mut wh: Vec<String> = Vec::new();
    wh.extend(p.resources.ids.iter().cloned());
    wh.extend(p.resources.environments.iter().map(|e| format!("{} servers", e)));
    wh.extend(p.resources.tags.iter().map(|t| format!("servers tagged {}", t)));
    let verb = if p.effect == Effect::Deny { "may never" } else { "may" };
    let uses = if p.max_uses == 1 { "once".to_string() } else { format!("up to {} times", p.max_uses) };
    let appr = match p.approval.required {
        0 => "without human approval".to_string(),
        1 => "after one human approval".to_string(),
        n => format!("after {} human approvals", n),
    };
    if p.effect == Effect::Deny {
        format!("{} {} {} on {}.", who, verb, what.join("; "), wh.join(", "))
    } else {
        format!(
            "{} {} {} {} on {} {}. Access expires after {}.",
            who,
            verb,
            what.join("; "),
            uses,
            wh.join(", "),
            appr,
            fmt_dur(p.max_duration_secs)
        )
    }
}
