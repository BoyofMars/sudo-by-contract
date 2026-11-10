import { describePolicy, formatDuration } from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, Empty, PageHeader, Skeleton } from "../../components/ui.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useAction, useIsAdmin, useLabels } from "../../lib/hooks.ts";
import { dateTime } from "../../lib/events.ts";
import { TEMPLATES } from "./PolicyBuilder.tsx";

export function Policies() {
  const { source } = useData();
  const label = useLabels();
  const isAdmin = useIsAdmin();
  const action = useAction();
  const q = useQuery((s) => s.policies(), [], { interval: 30_000 });
  const proposals = useQuery((s) => s.policyProposals().catch(() => []), [], { interval: 20_000 });
  const ov = useQuery((s) => s.overview(), []);
  const { identity } = useData();
  const quorum = ov.data?.config.policy_quorum ?? 1;
  const sorted = [...(q.data ?? [])].sort((a, b) => (a.effect === b.effect ? a.name.localeCompare(b.name) : a.effect === "Deny" ? -1 : 1));
  return (
    <div className="page">
      <PageHeader
        title="Policies"
        subtitle="Nothing is allowed by default. Deny always wins. Each policy is versioned and hashed on-chain."
        actions={isAdmin ? <a className="btn btn-primary" href="#/console/policies/new"><Icon name="plus" size={14} /> New policy</a> : null}
      />
      {quorum > 1 ? (
        <p className="quiet-note"><Icon name="shield" size={13} /> Policy changes need {quorum} distinct admins: a single compromised admin key cannot widen what agents may do.</p>
      ) : null}
      {proposals.data?.length ? (
        <section>
          <h2 className="section-title"><span>Pending policy changes</span><span className="count tone-pending">{proposals.data.length}</span></h2>
          <div className="policy-list">
            {proposals.data.map((pp) => {
              const mine = !!identity?.binding && pp.approvals.includes(identity.binding.principal);
              return (
                <article key={pp.id} className="policy-card proposal">
                  <div className="policy-sentence">
                    <Badge tone="pending" dot={false}>Proposed</Badge>
                    <p>{describePolicy(pp.policy, { agent: label })}</p>
                  </div>
                  <div className="policy-meta">
                    <span className="strong">{pp.policy.name}</span>
                    <span className="mono muted">{pp.policy.id} · proposal #{pp.id}</span>
                    <span className="muted">by {label(pp.proposer)}</span>
                    <span className="muted">{pp.approvals.length} of {quorum} admins: {pp.approvals.map(label).join(", ")}</span>
                    <span className="muted">expires {dateTime(pp.expires_at_ms)}</span>
                  </div>
                  {isAdmin ? (
                    <div className="policy-actions">
                      <button className="btn btn-primary btn-xs" disabled={mine || action.busy} title={mine ? "You already agreed; another admin must confirm" : undefined} onClick={() => action.run(() => source.confirmPolicy(pp.id), "Confirmation recorded")}>
                        {mine ? "Awaiting others" : "Confirm"}
                      </button>
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        </section>
      ) : null}
      {q.loading ? (
        <Skeleton lines={5} />
      ) : !sorted.length ? (
        <Empty title="No policies">Without a policy no agent can do anything. Start from a template.</Empty>
      ) : (
        <div className="policy-list">
          {sorted.map((p) => (
            <article key={p.id} className={"policy-card" + (p.status !== "Active" ? " is-off" : "")}>
              <div className="policy-sentence">
                {p.effect === "Deny" ? <Badge tone="danger" dot={false}>Deny</Badge> : null}
                <p>{describePolicy(p, { agent: label })}</p>
              </div>
              <div className="policy-meta">
                <span className="strong">{p.name}</span>
                <span className="mono muted">{p.id} · v{p.version}</span>
                <span className="muted">{p.approval.required === 0 ? "auto" : `${p.approval.required} approval${p.approval.required > 1 ? "s" : ""}`}</span>
                <span className="muted">≤ {formatDuration(p.max_duration_secs)} · {p.max_uses} use{p.max_uses > 1 ? "s" : ""}</span>
                <span className="muted">updated {dateTime(p.updated_at_ms)} by {label(p.updated_by)}</span>
                {p.status !== "Active" ? <Badge tone="muted">Disabled</Badge> : null}
              </div>
              {isAdmin ? (
                <div className="policy-actions">
                  <a className="btn btn-ghost btn-xs" href={`#/console/policies/${p.id}`}>Edit</a>
                  <button className="btn btn-ghost btn-xs" disabled={action.busy} onClick={() => action.run(() => source.setPolicyStatus(p.id, p.status === "Active" ? "Suspended" : "Active"), p.status === "Active" ? "Policy disabled" : "Policy enabled")}>
                    {p.status === "Active" ? "Disable" : "Enable"}
                  </button>
                </div>
              ) : (
                <div className="policy-actions">
                  <a className="btn btn-ghost btn-xs" href={`#/console/policies/${p.id}`}>View</a>
                </div>
              )}
            </article>
          ))}
        </div>
      )}
      {isAdmin ? (
        <section>
          <h2 className="section-title"><span>Start from a template</span></h2>
          <div className="templates">
            {TEMPLATES.map((t) => (
              <a key={t.key} className="template" href={`#/console/policies/new?template=${t.key}`}>
                <strong>{t.title}</strong>
                <span className="muted small">{t.blurb}</span>
              </a>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
