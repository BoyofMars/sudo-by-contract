import { useEffect, useState } from "react";
import type { Resource } from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, CopyButton, Empty, ErrorNote, Field, KV, PageHeader, Panel, Skeleton, Truncate, cx } from "../../components/ui.tsx";
import { RequestLine } from "../../components/domain.tsx";
import { useData, useNow, useQuery } from "../../lib/data/context.tsx";
import { useAction, useIsAdmin, useLabels } from "../../lib/hooks.ts";
import { dateTime, timeAgo } from "../../lib/events.ts";
import { EnrollInstructions } from "./Agents.tsx";
import type { EnrollmentToken } from "../../lib/data/source.ts";

function health(r: Resource, now: number): { tone: string; text: string } {
  if (r.status === "Pending") return { tone: "pending", text: "Awaiting enrollment" };
  if (r.status === "Disabled") return { tone: "danger", text: "Disabled" };
  if (r.last_seen_ms && now - r.last_seen_ms < 10 * 60_000) return { tone: "active", text: "Online" };
  return { tone: "muted", text: r.last_seen_ms ? `Last seen ${timeAgo(r.last_seen_ms, now)}` : "Never seen" };
}

export function Resources() {
  const q = useQuery((s) => s.resources(), [], { interval: 15_000 });
  const isAdmin = useIsAdmin();
  const now = useNow(30_000);
  return (
    <div className="page">
      <PageHeader
        title="Resources"
        subtitle="Hosts that trust the contract's certificate authority and enforce every action through the gate."
        actions={isAdmin ? <a className="btn btn-primary" href="#/console/resources/new"><Icon name="plus" size={14} /> Add resource</a> : null}
      />
      {q.loading ? (
        <Skeleton lines={4} />
      ) : !q.data?.length ? (
        <Empty title="No resources yet">Add a server and run one enrollment command on it.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Resource</th>
                <th>Environment</th>
                <th className="hide-md">Exposed services</th>
                <th>Gate</th>
                <th className="hide-md">Principal</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((r) => {
                const h = health(r, now);
                return (
                  <tr key={r.id} className="clickable" onClick={() => (window.location.hash = `#/console/resources/${r.id}`)}>
                    <td>
                      <a className="mono strong-link" href={`#/console/resources/${r.id}`}>{r.id}</a>
                      {r.label !== r.id ? <div className="cell-sub">{r.label}</div> : null}
                    </td>
                    <td><Badge tone="muted" dot={false}>{r.environment}</Badge></td>
                    <td className="hide-md mono small">{r.services.join(", ")}</td>
                    <td><Badge tone={h.tone}>{h.text}</Badge></td>
                    <td className="hide-md mono muted small">{r.principal}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function ResourceDetail({ id }: { id: string }) {
  const { source } = useData();
  const label = useLabels();
  const isAdmin = useIsAdmin();
  const action = useAction();
  const now = useNow(30_000);
  const q = useQuery((s) => s.resources(), [id], { interval: 10_000 });
  const ov = useQuery((s) => s.overview(), []);
  const reqs = useQuery((s) => s.requests({ resource_id: id, limit: 20 }), [id], { interval: 10_000 });
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const r = q.data?.find((x) => x.id === id);
  if (q.loading) return <div className="page"><Skeleton lines={6} /></div>;
  if (!r) return <div className="page"><Empty title={`Resource ${id} not found`} /></div>;
  const h = health(r, now);
  const env = ov.data?.environments.find((e) => e.name === r.environment);
  return (
    <div className="page">
      <PageHeader
        back={{ to: "/console/resources", label: "Resources" }}
        title={<span className="title-with-badge"><span className="mono">{r.id}</span> <Badge tone={h.tone}>{h.text}</Badge></span>}
        subtitle={r.label !== r.id ? r.label : `${r.environment} · ${r.services.length} services`}
        actions={
          isAdmin ? (
            <>
              <button className="btn btn-secondary" disabled={action.busy} onClick={async () => { const t = await action.run(() => source.createEnrollment("Gate", r.id, 3600)); if (t.ok) setToken(t.value); }}>
                <Icon name="key" size={14} /> {r.gate_key ? "Re-enroll host" : "Enrollment token"}
              </button>
              {r.status !== "Pending" ? (
                <button className={r.status === "Active" ? "btn btn-danger" : "btn btn-primary"} disabled={action.busy} onClick={() => action.run(() => source.setResourceStatus(r.id, r.status === "Active" ? "Disabled" : "Active"), r.status === "Active" ? "Resource disabled — every capability on it is now refused" : "Resource re-enabled")}>
                  {r.status === "Active" ? "Disable (kill switch)" : "Enable"}
                </button>
              ) : null}
            </>
          ) : null
        }
      />
      <ErrorNote error={action.error} />
      {token ? <Panel title="Enroll this host"><EnrollInstructions kind="gate" token={token} contractId={source.contractId} principal={r.id} /></Panel> : null}
      <div className="two-col">
        <Panel title="Enforcement">
          <KV
            cols={1}
            items={[
              ["Accepted principal", <span className="mono">{r.principal}</span>],
              ["Exposed services", <span className="mono">{r.services.join(", ")}</span>],
              ["Tags", r.tags.length ? r.tags.join(", ") : "—"],
              ["Gate key", r.gate_key ? <Truncate text={r.gate_key} head={18} tail={6} /> : "not enrolled"],
              ["Gate version", r.gate_version ?? "—"],
              ["Host key", r.host_fingerprint ? <Truncate text={r.host_fingerprint} head={16} tail={6} /> : "—"],
              ["Enrolled", r.enrolled_at_ms ? dateTime(r.enrolled_at_ms) : "—"],
              ["Last heartbeat", r.last_seen_ms ? timeAgo(r.last_seen_ms, now) : "—"],
            ]}
          />
        </Panel>
        <Panel title="Trusted certificate authority" actions={env?.ca_public_key_ssh ? <CopyButton text={env.ca_public_key_ssh} /> : null}>
          <p className="small muted">The host's <span className="mono">TrustedUserCAKeys</span>. Derived by the NEAR MPC network for this contract and path; no one holds its private key.</p>
          {env?.ca_public_key_ssh ? <pre className="code-block wrap">{env.ca_public_key_ssh}</pre> : <p className="quiet-note">CA not yet derived for {r.environment}.</p>}
          <p className="small muted mono">{env?.path}</p>
        </Panel>
      </div>
      <Panel title="Recent requests on this resource" flush>
        {reqs.data?.length ? <div className="list">{reqs.data.map((x) => <RequestLine key={x.id} r={x} label={label} />)}</div> : <Empty title="No requests yet" />}
      </Panel>
    </div>
  );
}

const STEPS = ["Describe", "Register", "Enroll host", "Ready"];

export function AddResource() {
  const { source } = useData();
  const action = useAction();
  const ov = useQuery((s) => s.overview(), []);
  const [step, setStep] = useState(0);
  const [f, setF] = useState({ id: "", label: "", environment: "production", services: "", tags: "" });
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const res = useQuery((s) => (step >= 2 ? s.resources() : Promise.resolve([])), [step], { interval: step === 2 ? 3000 : undefined });
  const created = res.data?.find((r) => r.id === f.id);

  useEffect(() => {
    if (step === 2 && created?.status === "Active") setStep(3);
  }, [step, created]);

  const services = f.services.split(/[\s,]+/).filter(Boolean);
  const tags = f.tags.split(/[\s,]+/).filter(Boolean);
  const slug = /^[a-z0-9](?:[a-z0-9]|-(?!-)){0,61}[a-z0-9]$/;
  const unitOk = services.every((s) => /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,99}$/.test(s) && !s.includes(".."));
  const valid = slug.test(f.id) && services.length > 0 && services.length <= 32 && unitOk && tags.every((t) => slug.test(t));

  return (
    <div className="page narrow">
      <PageHeader back={{ to: "/console/resources", label: "Resources" }} title="Add resource" subtitle="Enroll a Linux host so agents can be granted typed, time-boxed actions on it — and nothing else." />
      <ol className="stepper">
        {STEPS.map((s, i) => (
          <li key={s} className={cx(i < step && "done", i === step && "on")}>
            <span>{i < step ? <Icon name="check" size={12} /> : i + 1}</span>
            {s}
          </li>
        ))}
      </ol>

      {step === 0 ? (
        <Panel>
          <form className="form" onSubmit={(e) => { e.preventDefault(); setStep(1); }}>
            <div className="form-row">
              <Field label="Resource id" hint={<>Becomes the certificate principal <span className="mono">sbc-{f.id || "…"}</span>. Public on-chain — use an alias if topology is sensitive.</>}>
                <input className="input mono" value={f.id} onChange={(e) => setF({ ...f, id: e.target.value.toLowerCase() })} placeholder="prod-web-04" autoFocus />
              </Field>
              <Field label="Label" hint="Optional. Shown to people.">
                <input className="input" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} placeholder="prod-web-04 (eu-west)" />
              </Field>
            </div>
            <div className="form-row">
              <Field label="Environment" hint="Each environment has its own MPC-derived CA.">
                <select className="select" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>
                  {(ov.data?.environments ?? []).map((e) => <option key={e.name} value={e.name}>{e.name}</option>)}
                </select>
              </Field>
              <Field label="Tags" hint="Optional, comma separated slugs.">
                <input className="input" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="web, eu" />
              </Field>
            </div>
            <Field label="Services the gate exposes" hint="systemd units / supervisor programs. Requests for anything else are rejected before policy is consulted.">
              <input className="input mono" value={f.services} onChange={(e) => setF({ ...f, services: e.target.value })} placeholder="checkout-api, nginx" />
            </Field>
            {!unitOk ? <p className="field-hint err">Service names may not start with “-” or contain spaces, slashes or shell characters.</p> : null}
            <div className="form-actions">
              <button className="btn btn-primary" disabled={!valid}>Continue</button>
            </div>
          </form>
        </Panel>
      ) : null}

      {step === 1 ? (
        <Panel title="Review">
          <KV cols={2} items={[["Resource", <span className="mono">{f.id}</span>], ["Environment", f.environment], ["Principal", <span className="mono">sbc-{f.id}</span>], ["Services", <span className="mono">{services.join(", ")}</span>]]} />
          <p className="small muted">Registering creates the resource on the policy contract in state <em>Pending</em>, then a one-time enrollment token the host uses to bind its own gate key.</p>
          <ErrorNote error={action.error} />
          <div className="form-actions">
            <button className="btn btn-secondary" onClick={() => setStep(0)}>Back</button>
            <button
              className="btn btn-primary"
              disabled={action.busy}
              onClick={async () => {
                const a = await action.run(() => source.createResource({ id: f.id, label: f.label.trim() || f.id, environment: f.environment, tags, services }));
                if (!a.ok) return;
                const t = await action.run(() => source.createEnrollment("Gate", f.id, 3600));
                if (t.ok) {
                  setToken(t.value);
                  setStep(2);
                }
              }}
            >
              {action.busy ? "Registering on NEAR…" : "Register & create token"}
            </button>
          </div>
        </Panel>
      ) : null}

      {step === 2 && token ? (
        <>
          <Panel title="Run on the host">
            <EnrollInstructions kind="gate" token={token} contractId={source.contractId} principal={f.id} />
          </Panel>
          <Panel title="Exactly what this changes on the host">
            <ul className="explain">
              <li><strong>/etc/ssh/sbc_user_ca.pub</strong> — the environment's CA public key (MPC-derived), referenced by <span className="mono">TrustedUserCAKeys</span>.</li>
              <li><strong>/etc/ssh/sbc_principals/sbc-agent</strong> — the single principal <span className="mono">sbc-{f.id}</span> (<span className="mono">AuthorizedPrincipalsFile</span>). Certificates for any other host are refused.</li>
              <li><strong>sshd_config</strong> — <span className="mono">Match User sbc-agent</span>: <span className="mono">ForceCommand /usr/local/sbin/sbc-gate</span>, <span className="mono">ExposeAuthInfo yes</span>, no PTY, no forwarding, <span className="mono">RevokedKeys /etc/ssh/sbc_revoked.krl</span>.</li>
              <li><strong>sbc-agent</strong> — a locked local user with no password and no authorized_keys; certificates are its only way in.</li>
              <li><strong>/etc/sudoers.d/sbc</strong> — exact command lines for {services.map((s) => <span key={s} className="mono">{s} </span>)} only (restart/status/journal). No wildcards, no shell.</li>
              <li><strong>/etc/sbc/gate.toml + gate.key</strong> — the gate's own key (generated on the host, never leaves it), which can only call <span className="mono">consume</span>, <span className="mono">report_denial</span>, <span className="mono">heartbeat</span>.</li>
              <li><strong>sbc-gate-sync.timer</strong> — every minute: heartbeat + pull revoked serials into the KRL.</li>
            </ul>
            <p className="small muted">Nothing is piped from the internet into a root shell: the command runs a binary you installed, and prints every file it will write before writing it.</p>
          </Panel>
          <div className="waiting">
            <span className="pulse" /> Waiting for <span className="mono">{f.id}</span> to enroll… {source.mode === "preview" ? <em className="muted">(simulated host enrolls in a few seconds)</em> : null}
          </div>
        </>
      ) : null}

      {step === 3 && created ? (
        <Panel title="Ready">
          <div className="ready">
            <Icon name="check" size={20} />
            <div>
              <strong><span className="mono">{created.id}</span> is enrolled and reporting.</strong>
              <p className="muted">Gate {created.gate_version ?? ""} · key <Truncate text={created.gate_key ?? ""} head={14} tail={6} />. Agents still can't touch it until a policy grants something.</p>
            </div>
          </div>
          <div className="form-actions">
            <a className="btn btn-secondary" href={`#/console/resources/${created.id}`}>View resource</a>
            <a className="btn btn-primary" href="#/console/policies/new?template=restart">Create a policy for it</a>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
