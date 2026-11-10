import { useEffect, useMemo, useState, type ReactNode } from "react";
import { ACTION_VERBS, describePolicy, formatDuration, type PolicyInput, type SimulateResult } from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, Chips, ErrorNote, Field, PageHeader, Panel, Segmented, Skeleton } from "../../components/ui.tsx";
import { PolicyChecks } from "../../components/domain.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useAction, useIsAdmin, useLabels } from "../../lib/hooks.ts";
import { evaluate, validatePolicy } from "../../lib/policyEval.ts";
import { navigate } from "../../lib/router.tsx";
import { useToast } from "../../components/toast.tsx";

const none = { utc_hours: null, require_source_address: false } as PolicyInput["conditions"];

export const TEMPLATES: { key: string; title: string; blurb: string; make: () => PolicyInput }[] = [
  {
    key: "restart",
    title: "Service restart",
    blurb: "One service. One use. 10 minutes. One human approval.",
    make: () => ({ id: "service-restart", name: "Service restart", description: "Restart one named service after a human looks at the evidence.", effect: "Allow", subjects: { all_agents: false, agents: [] }, resources: { ids: [], environments: ["production"], tags: [] }, actions: [{ kind: "service.restart", targets: [] }], max_duration_secs: 600, max_uses: 1, approval: { required: 1, approvers: [] }, conditions: none }),
  },
  {
    key: "logs",
    title: "Log inspection",
    blurb: "Read-only journal access. 15 minutes. Policy approves.",
    make: () => ({ id: "log-inspection", name: "Log inspection", description: "Read-only journal access for triage.", effect: "Allow", subjects: { all_agents: true, agents: [] }, resources: { ids: [], environments: ["production", "staging"], tags: [] }, actions: [{ kind: "logs.read", targets: ["*"] }], max_duration_secs: 900, max_uses: 5, approval: { required: 0, approvers: [] }, conditions: none }),
  },
  {
    key: "status",
    title: "Status check",
    blurb: "systemctl status on any enrolled service. Policy approves.",
    make: () => ({ id: "status-checks", name: "Status checks", description: "", effect: "Allow", subjects: { all_agents: true, agents: [] }, resources: { ids: [], environments: ["production", "staging"], tags: [] }, actions: [{ kind: "service.status", targets: ["*"] }], max_duration_secs: 600, max_uses: 10, approval: { required: 0, approvers: [] }, conditions: none }),
  },
  {
    key: "emergency",
    title: "Emergency remediation",
    blurb: "Restart any enrolled service. 5 minutes. Two approvals.",
    make: () => ({ id: "emergency-remediation", name: "Emergency remediation", description: "Break-glass restarts. Two humans must agree; the window is short.", effect: "Allow", subjects: { all_agents: false, agents: [] }, resources: { ids: [], environments: ["production"], tags: [] }, actions: [{ kind: "service.restart", targets: ["*"] }], max_duration_secs: 300, max_uses: 1, approval: { required: 2, approvers: [] }, conditions: none }),
  },
  {
    key: "deny-sshd",
    title: "Never touch sshd",
    blurb: "An explicit deny. Wins over every allow.",
    make: () => ({ id: "never-touch-sshd", name: "Never touch sshd", description: "Restarting sshd can lock everyone out.", effect: "Deny", subjects: { all_agents: true, agents: [] }, resources: { ids: [], environments: ["production", "staging"], tags: [] }, actions: [{ kind: "service.restart", targets: ["sshd"] }], max_duration_secs: 60, max_uses: 1, approval: { required: 0, approvers: [] }, conditions: none }),
  },
];

const DURATIONS = [60, 120, 300, 600, 900, 1800, 3600, 7200, 14400];

const BLANK_WHO = "[which agents?]";
/** Show the unfinished parts of the sentence instead of silently dropping them. */
function withBlanks(p: PolicyInput): PolicyInput {
  const q = structuredClone(p);
  if (!q.subjects.all_agents && !q.subjects.agents.length) q.subjects.agents = [BLANK_WHO];
  if (q.actions[0] && !q.actions[0].targets.length) q.actions[0].targets = ["[which services?]"];
  if (!q.resources.ids.length && !q.resources.environments.length && !q.resources.tags.length) q.resources.ids = ["[where?]"];
  return q;
}

export function PolicyBuilder({ id, template }: { id?: string; template?: string | null }) {
  const { source } = useData();
  const label = useLabels();
  const isAdmin = useIsAdmin();
  const action = useAction();
  const toast = useToast();
  const existing = useQuery((s) => (id ? s.policy(id) : Promise.resolve(null)), [id]);
  const agents = useQuery((s) => s.agents(), []);
  const approvers = useQuery((s) => s.approvers(), []);
  const resources = useQuery((s) => s.resources(), []);
  const ov = useQuery((s) => s.overview(), []);
  const [p, setP] = useState<PolicyInput | null>(id ? null : (TEMPLATES.find((t) => t.key === template) ?? TEMPLATES[0]).make());
  const [showJson, setShowJson] = useState(false);

  useEffect(() => {
    if (id && existing.data && !p) {
      const { version: _v, status: _s, updated_at_ms: _u, updated_by: _b, hash: _h, ...input } = existing.data;
      void _v; void _s; void _u; void _b; void _h;
      setP(input);
    }
  }, [id, existing.data, p]);

  const envs = ov.data?.environments.map((e) => e.name) ?? [];
  const services = useMemo(() => [...new Set((resources.data ?? []).flatMap((r) => r.services))].sort(), [resources.data]);
  const tags = useMemo(() => [...new Set((resources.data ?? []).flatMap((r) => r.tags))].sort(), [resources.data]);

  if (id && existing.loading) return <div className="page"><Skeleton lines={8} /></div>;
  if (!p) return <div className="page"><Skeleton lines={8} /></div>;

  const err = validatePolicy(p, ov.data?.config.max_duration_secs);
  const quorum = ov.data?.config.policy_quorum ?? 1;
  const kind = p.actions[0]?.kind ?? "service.restart";
  const targets = p.actions[0]?.targets ?? [];
  const set = (patch: Partial<PolicyInput>) => setP({ ...p, ...patch });
  const setAction = (k: string, t: string[]) => set({ actions: [{ kind: k, targets: t }] });
  const readOnly = !isAdmin;

  return (
    <div className="page builder">
      <PageHeader back={{ to: "/console/policies", label: "Policies" }} title={id ? `Edit ${existing.data?.name ?? id}` : "New policy"} subtitle={id ? `Saving creates version ${(existing.data?.version ?? 0) + 1}. Requests keep the version they were evaluated against.` : "Describe intent; the contract enforces the structure underneath."} />

      {!id ? (
        <div className="templates templates-inline">
          {TEMPLATES.map((t) => (
            <button key={t.key} className={"template" + (template === t.key ? " on" : "")} onClick={() => { setP(t.make()); navigate(`/console/policies/new?template=${t.key}`); }}>
              <strong>{t.title}</strong>
              <span className="muted small">{t.blurb}</span>
            </button>
          ))}
        </div>
      ) : null}

      <div className="sentence-bar" aria-live="polite">
        {p.effect === "Deny" ? <Badge tone="danger" dot={false}>Deny</Badge> : <Badge tone="active" dot={false}>Allow</Badge>}
        <p>{describePolicy(withBlanks(p), { agent: (x) => (x === BLANK_WHO ? x : label(x)) })}</p>
      </div>

      <div className="builder-grid">
        <fieldset className="builder-form" disabled={readOnly}>
          <Row k="Effect">
            <Segmented value={p.effect} onChange={(v) => set({ effect: v })} options={[{ value: "Allow", label: "Allow" }, { value: "Deny", label: "Deny (always wins)" }]} />
          </Row>
          <Row k="Who">
            <label className="check-inline">
              <input type="checkbox" checked={p.subjects.all_agents} onChange={(e) => set({ subjects: { all_agents: e.target.checked, agents: e.target.checked ? [] : p.subjects.agents } })} /> Any registered agent
            </label>
            {!p.subjects.all_agents ? <Chips options={(agents.data ?? []).map((a) => ({ value: a.id, label: a.label }))} value={p.subjects.agents} onChange={(v) => set({ subjects: { all_agents: false, agents: v } })} /> : null}
          </Row>
          <Row k="Can">
            <Segmented
              value={kind}
              onChange={(v) => setAction(v, targets)}
              options={Object.entries(ACTION_VERBS).map(([k, v]) => ({ value: k, label: v.title.replace(" of", "") }))}
            />
            <span className="field-hint">{ACTION_VERBS[kind]?.readOnly ? "Read-only action." : "Mutating action — consider requiring approval."}</span>
          </Row>
          <Row k="Targets">
            <label className="check-inline">
              <input type="checkbox" checked={targets.includes("*")} onChange={(e) => setAction(kind, e.target.checked ? ["*"] : [])} /> Any service the host exposes
            </label>
            {!targets.includes("*") ? <Chips mono options={services.map((s) => ({ value: s }))} value={targets} onChange={(v) => setAction(kind, v)} /> : null}
          </Row>
          <Row k="On">
            <div className="sub-label">Environments</div>
            <Chips options={envs.map((e) => ({ value: e }))} value={p.resources.environments} onChange={(v) => set({ resources: { ...p.resources, environments: v } })} />
            <div className="sub-label">Specific resources</div>
            <Chips mono options={(resources.data ?? []).map((r) => ({ value: r.id }))} value={p.resources.ids} onChange={(v) => set({ resources: { ...p.resources, ids: v } })} />
            {tags.length ? (
              <>
                <div className="sub-label">Tags</div>
                <Chips options={tags.map((t) => ({ value: t }))} value={p.resources.tags} onChange={(v) => set({ resources: { ...p.resources, tags: v } })} />
              </>
            ) : null}
          </Row>
          {p.effect === "Allow" ? (
            <>
              <Row k="For at most">
                <select className="select" value={p.max_duration_secs} onChange={(e) => set({ max_duration_secs: Number(e.target.value) })}>
                  {DURATIONS.filter((d) => d <= (ov.data?.config.max_duration_secs ?? 14400)).map((d) => <option key={d} value={d}>{formatDuration(d)}</option>)}
                </select>
              </Row>
              <Row k="Uses">
                <input className="input input-num" type="number" min={1} max={100} value={p.max_uses} onChange={(e) => set({ max_uses: Math.max(1, Math.min(100, Number(e.target.value) || 1)) })} />
                <span className="field-hint">{p.max_uses === 1 ? "Single use: the capability closes after one successful command, even if time remains." : "Each successful command consumes one use."}</span>
              </Row>
              <Row k="Requires">
                <Segmented
                  value={String(p.approval.required)}
                  onChange={(v) => set({ approval: { ...p.approval, required: Number(v) } })}
                  options={[{ value: "0", label: "Policy only" }, { value: "1", label: "1 human" }, { value: "2", label: "2 humans" }, { value: "3", label: "3 humans" }]}
                />
                {p.approval.required > 0 ? (
                  <>
                    <div className="sub-label">Eligible approvers <span className="muted">(none selected = any approver)</span></div>
                    <Chips options={(approvers.data ?? []).map((a) => ({ value: a.id, label: a.label }))} value={p.approval.approvers} onChange={(v) => set({ approval: { ...p.approval, approvers: v } })} />
                  </>
                ) : null}
              </Row>
              <Row k="Conditions">
                <label className="check-inline">
                  <input type="checkbox" checked={!!p.conditions.utc_hours} onChange={(e) => set({ conditions: { ...p.conditions, utc_hours: e.target.checked ? [8, 18] : null } })} /> Only during a UTC window
                </label>
                {p.conditions.utc_hours ? (
                  <div className="inline-fields">
                    <input className="input input-num" type="number" min={0} max={23} value={p.conditions.utc_hours[0]} onChange={(e) => set({ conditions: { ...p.conditions, utc_hours: [Number(e.target.value), p.conditions.utc_hours![1]] } })} />
                    <span>to</span>
                    <input className="input input-num" type="number" min={0} max={24} value={p.conditions.utc_hours[1]} onChange={(e) => set({ conditions: { ...p.conditions, utc_hours: [p.conditions.utc_hours![0], Number(e.target.value)] } })} />
                    <span className="muted">UTC</span>
                  </div>
                ) : null}
                <label className="check-inline">
                  <input type="checkbox" checked={p.conditions.require_source_address} onChange={(e) => set({ conditions: { ...p.conditions, require_source_address: e.target.checked } })} /> Certificate must be bound to the agent's source address
                </label>
              </Row>
            </>
          ) : null}
          <Row k="Name">
            <div className="form-row">
              <input className="input" value={p.name} onChange={(e) => set({ name: e.target.value })} placeholder="Production service remediation" />
              <input className="input mono" value={p.id} onChange={(e) => set({ id: e.target.value.toLowerCase() })} placeholder="policy-id" disabled={!!id} />
            </div>
            <textarea className="textarea" rows={2} value={p.description} onChange={(e) => set({ description: e.target.value })} placeholder="Why this policy exists (shown to approvers)" maxLength={500} />
          </Row>

          <details className="json" open={showJson} onToggle={(e) => setShowJson((e.target as HTMLDetailsElement).open)}>
            <summary>Advanced: policy as submitted to <span className="mono">upsert_policy</span></summary>
            <pre className="code-block">{JSON.stringify(p, null, 2)}</pre>
          </details>

          {err ? <p className="field-hint err"><Icon name="alert" size={12} /> {err}</p> : null}
          <ErrorNote error={action.error} />
          {isAdmin ? (
            <div className="form-actions sticky-actions">
              <a className="btn btn-secondary" href="#/console/policies">Cancel</a>
              <button
                className="btn btn-primary"
                disabled={!!err || action.busy}
                onClick={async () => {
                  const r = await action.run(() => source.upsertPolicy(p));
                  if (!r.ok) return;
                  toast(
                    r.value === 0
                      ? `Proposed. ${quorum} admins must agree before this policy changes.`
                      : `Policy saved on-chain as version ${r.value}`,
                    "success",
                  );
                  navigate("/console/policies");
                }}
              >
                {action.busy ? "Saving on NEAR…" : quorum > 1 ? "Propose change" : id ? `Save version ${(existing.data?.version ?? 0) + 1}` : "Save policy"}
              </button>
            </div>
          ) : null}
        </fieldset>

        <TestPanel draft={p} />
      </div>
    </div>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="b-row">
      <div className="b-key">{k}</div>
      <div className="b-val">{children}</div>
    </div>
  );
}

function TestPanel({ draft }: { draft: PolicyInput }) {
  const label = useLabels();
  const agents = useQuery((s) => s.agents(), []);
  const resources = useQuery((s) => s.resources(), []);
  const policies = useQuery((s) => s.policies(), []);
  const [agent, setAgent] = useState("");
  const [resource, setResource] = useState("");
  const [target, setTarget] = useState("");
  const [dur, setDur] = useState(600);
  const [onChain, setOnChain] = useState<SimulateResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const { source } = useData();

  const a = agents.data?.find((x) => x.id === (agent || agents.data?.[0]?.id));
  const r = resources.data?.find((x) => x.id === (resource || resources.data?.[0]?.id));
  const t = target || r?.services[0] || "";
  const kind = draft.actions[0]?.kind ?? "service.restart";
  const action = `${kind}:${t}`;

  // local evaluation: on-chain policies with this draft replacing its saved version
  const local = useMemo(() => {
    if (!a || !r || !t) return null;
    if (!r.services.includes(t)) return { outcome: { kind: "rejected" as const }, checks: [{ name: "resource", ok: false, detail: `${r.id} does not expose ${t}` }], policy: null };
    const others = (policies.data ?? []).filter((x) => x.id !== draft.id);
    return evaluate([...others, draft], { agent: a, resource: r, action, durationSecs: dur, uses: 1, sourceAddress: null, nowMs: Date.now() });
  }, [a, r, t, action, dur, draft, policies.data]);

  return (
    <aside className="test-panel">
      <Panel title="Test this policy">
        <div className="form">
          <Field label="Agent">
            <select className="select" value={a?.id ?? ""} onChange={(e) => setAgent(e.target.value)}>
              {(agents.data ?? []).map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}
            </select>
          </Field>
          <Field label="Resource">
            <select className="select" value={r?.id ?? ""} onChange={(e) => { setResource(e.target.value); setTarget(""); }}>
              {(resources.data ?? []).map((x) => <option key={x.id} value={x.id}>{x.id}</option>)}
            </select>
          </Field>
          <div className="form-row">
            <Field label={ACTION_VERBS[kind]?.title ?? kind}>
              <select className="select mono" value={t} onChange={(e) => setTarget(e.target.value)}>
                {(r?.services ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="For">
              <select className="select" value={dur} onChange={(e) => setDur(Number(e.target.value))}>
                {DURATIONS.map((d) => <option key={d} value={d}>{formatDuration(d)}</option>)}
              </select>
            </Field>
          </div>
        </div>
        {local ? (
          <div className="test-result">
            <div className="test-head">
              <span>Draft</span>
              <OutcomeBadge kind={local.outcome.kind} n={"required" in local.outcome ? local.outcome.required : 0} />
              <span className="muted small">{local.policy ? `via ${local.policy.name}` : ""}</span>
            </div>
            <PolicyChecks checks={local.checks} label={label} />
            <p className="small muted">Evaluated in your browser with a mirror of the contract's logic, including this unsaved draft.</p>
          </div>
        ) : null}
        <button
          className="btn btn-secondary btn-block"
          disabled={!a || !r || !t || busy}
          onClick={async () => {
            setBusy(true);
            setErr(null);
            try {
              setOnChain(await source.simulate({ agent_id: a!.id, resource_id: r!.id, action, duration_secs: dur }));
            } catch (e) {
              setErr(e instanceof Error ? e.message : String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Asking the contract…" : "Simulate against on-chain policies"}
        </button>
        {err ? <p className="field-hint err">{err}</p> : null}
        {onChain ? (
          <div className="test-result">
            <div className="test-head">
              <span>On-chain</span>
              <OutcomeBadge kind={onChain.outcome === "auto_approved" ? "auto" : onChain.outcome === "needs_approval" ? "approval" : "rejected"} n={onChain.required_approvals} />
              <span className="muted small">{onChain.policy_name ? `via ${onChain.policy_name}` : ""}</span>
            </div>
            <PolicyChecks checks={onChain.checks} label={label} />
            <p className="small muted">Result of the contract's <span className="mono">simulate</span> view — saved policies only.</p>
          </div>
        ) : null}
      </Panel>
    </aside>
  );
}

function OutcomeBadge({ kind, n }: { kind: "auto" | "approval" | "rejected"; n: number }) {
  if (kind === "auto") return <Badge tone="active">Auto-approved</Badge>;
  if (kind === "approval") return <Badge tone="pending">{n} approval{n > 1 ? "s" : ""} needed</Badge>;
  return <Badge tone="danger">Rejected</Badge>;
}
