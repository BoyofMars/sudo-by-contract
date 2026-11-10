import { useState } from "react";
import type { Agent } from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, Command, Dialog, Empty, ErrorNote, Field, KV, PageHeader, Panel, Skeleton, Truncate } from "../../components/ui.tsx";
import { RequestLine } from "../../components/domain.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useAction, useIsAdmin, useLabels } from "../../lib/hooks.ts";
import { dateTime } from "../../lib/events.ts";
import type { EnrollmentToken } from "../../lib/data/source.ts";

export function Agents() {
  const q = useQuery((s) => s.agents(), [], { interval: 15_000 });
  const isAdmin = useIsAdmin();
  const [open, setOpen] = useState(false);
  return (
    <div className="page">
      <PageHeader
        title="Agents"
        subtitle="Identities that can ask for capabilities. An agent is its keys; everything else is a label."
        actions={isAdmin ? <button className="btn btn-primary" onClick={() => setOpen(true)}><Icon name="plus" size={14} /> Register agent</button> : null}
      />
      {q.loading ? (
        <Skeleton lines={4} />
      ) : !q.data?.length ? (
        <Empty title="No agents yet">Register an agent, then enroll it with <span className="mono">sudoctl enroll</span>.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Agent</th>
                <th className="hide-md">Owner</th>
                <th>Status</th>
                <th className="num">Requests</th>
                <th className="num hide-md">Approved</th>
                <th className="num hide-md">Rejected</th>
                <th className="num">Allowed</th>
                <th className="num">Denied</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.id} className="clickable" onClick={() => (window.location.hash = `#/console/agents/${a.id}`)}>
                  <td>
                    <a href={`#/console/agents/${a.id}`} className="strong-link">{a.label}</a>
                    <div className="cell-sub mono">{a.id}</div>
                  </td>
                  <td className="hide-md">{a.owner}</td>
                  <td><Badge tone={a.status === "Active" ? "active" : "muted"}>{a.status === "Active" ? (a.keys.length ? "Enrolled" : "Awaiting key") : "Suspended"}</Badge></td>
                  <td className="num mono">{a.stats.requests}</td>
                  <td className="num mono hide-md">{a.stats.approved + a.stats.auto_approved}</td>
                  <td className="num mono hide-md">{a.stats.rejected}</td>
                  <td className="num mono">{a.stats.actions_allowed}</td>
                  <td className="num mono">{a.stats.actions_denied ? <span className="danger-text">{a.stats.actions_denied}</span> : 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <RegisterAgent open={open} onClose={() => setOpen(false)} />
    </div>
  );
}

function RegisterAgent({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { source } = useData();
  const action = useAction();
  const [f, setF] = useState({ id: "", label: "", owner: "", runtime: "" });
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const valid = /^[a-z0-9](?:[a-z0-9]|-(?!-)){0,61}[a-z0-9]$/.test(f.id) && f.label.trim();
  return (
    <Dialog open={open} onClose={() => { setToken(null); onClose(); }} title={token ? "Enroll the agent" : "Register agent"} wide>
      {token ? (
        <EnrollInstructions kind="agent" token={token} contractId={source.contractId} principal={f.id} />
      ) : (
        <form
          className="form"
          onSubmit={async (e) => {
            e.preventDefault();
            const r1 = await action.run(() => source.createAgent({ id: f.id, label: f.label.trim(), owner: f.owner.trim(), runtime: f.runtime.trim() }));
            if (!r1.ok) return;
            const r2 = await action.run(() => source.createEnrollment("Agent", f.id, 3600));
            if (r2.ok) setToken(r2.value);
          }}
        >
          <Field label="Agent id" hint="Slug. Appears in certificates' key id and the audit log.">
            <input className="input mono" value={f.id} onChange={(e) => setF({ ...f, id: e.target.value.toLowerCase() })} placeholder="deploy-agent" autoFocus />
          </Field>
          <Field label="Display name">
            <input className="input" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} placeholder="Deploy Agent" />
          </Field>
          <div className="form-row">
            <Field label="Accountable owner" hint="Display metadata only.">
              <input className="input" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} placeholder="platform-team" />
            </Field>
            <Field label="Runtime" hint="Self-described; never used for authorization.">
              <input className="input" value={f.runtime} onChange={(e) => setF({ ...f, runtime: e.target.value })} placeholder="claude-opus-5-5 · Agent SDK" />
            </Field>
          </div>
          <ErrorNote error={action.error} />
          <div className="form-actions">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" disabled={!valid || action.busy}>{action.busy ? "Registering on NEAR…" : "Register & create enrollment token"}</button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

export function EnrollInstructions({ kind, token, contractId, principal }: { kind: "agent" | "gate"; token: EnrollmentToken; contractId: string; principal: string }) {
  const cmd =
    kind === "agent"
      ? `sudoctl enroll --contract ${contractId} --token ${token.token}`
      : `sudo sbc-gate enroll --contract ${contractId} --resource ${principal} --token ${token.token}`;
  return (
    <div className="enroll">
      <p>
        Run this {kind === "agent" ? "where the agent runs" : "on the host, as root"}. It generates a key locally, binds it to <span className="mono">{principal}</span>, and burns this one-time token.
        The token expires at {new Date(token.expiresAtMs).toLocaleTimeString()} and can only call <span className="mono">complete_enrollment</span>.
      </p>
      <Command>{cmd}</Command>
      <p className="small muted">
        Treat the token like a password until it is used. The private key it creates never leaves the {kind === "agent" ? "agent's machine" : "host"}; the console never sees it.
      </p>
    </div>
  );
}

export function AgentDetail({ id }: { id: string }) {
  const { source } = useData();
  const label = useLabels();
  const isAdmin = useIsAdmin();
  const action = useAction();
  const agents = useQuery((s) => s.agents(), [id], { interval: 15_000 });
  const reqs = useQuery((s) => s.requests({ agent_id: id, limit: 30 }), [id], { interval: 10_000 });
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const a: Agent | undefined = agents.data?.find((x) => x.id === id);
  if (agents.loading) return <div className="page"><Skeleton lines={6} /></div>;
  if (!a) return <div className="page"><Empty title={`Agent ${id} not found`} /></div>;
  const s = a.stats;
  return (
    <div className="page">
      <PageHeader
        back={{ to: "/console/agents", label: "Agents" }}
        title={<span className="title-with-badge">{a.label} <Badge tone={a.status === "Active" ? "active" : "muted"}>{a.status}</Badge></span>}
        subtitle={<span className="mono">{a.id}</span>}
        actions={
          isAdmin ? (
            <>
              <button className="btn btn-secondary" disabled={action.busy} onClick={async () => { const r = await action.run(() => source.createEnrollment("Agent", a.id, 3600)); if (r.ok) setToken(r.value); }}>
                <Icon name="key" size={14} /> New key enrollment
              </button>
              <button className={a.status === "Active" ? "btn btn-danger" : "btn btn-primary"} disabled={action.busy} onClick={() => action.run(() => source.setAgentStatus(a.id, a.status === "Active" ? "Suspended" : "Active"), a.status === "Active" ? "Agent suspended" : "Agent reactivated")}>
                {a.status === "Active" ? "Suspend" : "Reactivate"}
              </button>
            </>
          ) : null
        }
      />
      <div className="stats-row">
        <Stat k="Requests" v={s.requests} />
        <Stat k="Approved" v={s.approved + s.auto_approved} sub={`${s.auto_approved} by policy`} />
        <Stat k="Denied / rejected" v={s.denied + s.rejected} />
        <Stat k="Revoked" v={s.revoked} />
        <Stat k="Actions allowed" v={s.actions_allowed} />
        <Stat k="Actions denied" v={s.actions_denied} tone={s.actions_denied ? "danger" : undefined} sub="escalation attempts stopped at the host" />
      </div>
      <div className="two-col">
        <Panel title="Cryptographic identity">
          <p className="small muted">What authorization actually checks: function-call keys on <span className="mono">{source.contractId}</span>, restricted by the protocol to <span className="mono">request_access</span> and <span className="mono">cancel_request</span>.</p>
          {a.keys.length ? (
            <ul className="keylist">
              {a.keys.map((k) => <li key={k}><Icon name="key" size={13} /> <Truncate text={k} head={20} tail={8} /></li>)}
            </ul>
          ) : (
            <p className="quiet-note">No key enrolled yet.</p>
          )}
        </Panel>
        <Panel title="Display metadata">
          <p className="small muted">Self-described. Shown to people, never used for authorization.</p>
          <KV cols={1} items={[["Owner", a.owner || "—"], ["Runtime", a.runtime || "—"], ["Registered", dateTime(a.created_at_ms)]]} />
        </Panel>
      </div>
      {token ? <Panel title="Enrollment token"><EnrollInstructions kind="agent" token={token} contractId={source.contractId} principal={a.id} /></Panel> : null}
      <Panel title="Recent requests" flush>
        {reqs.data?.length ? <div className="list">{reqs.data.map((r) => <RequestLine key={r.id} r={r} label={label} />)}</div> : <Empty title="No requests yet" />}
      </Panel>
    </div>
  );
}

export function Stat({ k, v, sub, tone }: { k: string; v: number | string; sub?: string; tone?: string }) {
  return (
    <div className="stat">
      <span className="stat-k">{k}</span>
      <span className={"stat-v mono " + (tone ? `${tone}-text` : "")}>{v}</span>
      {sub ? <span className="stat-sub">{sub}</span> : null}
    </div>
  );
}
