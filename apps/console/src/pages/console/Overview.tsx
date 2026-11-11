import { actionTitle, formatDuration, type AccessRequest } from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, Countdown, Empty, PageHeader, Panel, Skeleton, StateBadge, Truncate, cx } from "../../components/ui.tsx";
import { DenialRow, RequestLine, WindowBar } from "../../components/domain.tsx";
import { useData, useNow, useQuery } from "../../lib/data/context.tsx";
import { useCanApprove, useLabels } from "../../lib/hooks.ts";
import { denialsOf, timeAgo } from "../../lib/events.ts";

export function Overview() {
  const { source } = useData();
  const label = useLabels();
  const canApprove = useCanApprove();
  const now = useNow(5000);
  const reqs = useQuery((s) => s.requests({ limit: 60 }), [], { interval: 5000 });
  const ov = useQuery((s) => s.overview(), [], { interval: 15_000 });
  const resources = useQuery((s) => s.resources(), [], { interval: 30_000 });
  const reports = useQuery((s) => s.gateReports({ limit: 50 }), [], { interval: 15_000 });
  const relay = useQuery((s) => s.relayState(), [], { interval: 60_000 });

  const all = reqs.data ?? [];
  const pending = all.filter((r) => r.state === "PendingApproval");
  const live = all.filter((r) => r.state === "Active" || r.state === "Signing");
  const denials = denialsOf(all, reports.data ?? []).slice(0, 5);
  const done = all.filter((r) => ["Exhausted", "Expired", "Revoked", "Cancelled", "Denied", "Rejected"].includes(r.state)).slice(0, 6);
  // disabled hosts are not expected to report in
  const activeHosts = (resources.data ?? []).filter((r) => r.status === "Active");
  const online = activeHosts.filter((r) => r.last_seen_ms && now - r.last_seen_ms < 10 * 60_000).length;
  const lastHeartbeat = Math.max(0, ...activeHosts.map((r) => r.last_seen_ms ?? 0));

  return (
    <div className="page">
      <PageHeader
        title="Overview"
        subtitle={reqs.loading ? "Reading the contract…" : pending.length ? `${pending.length} request${pending.length > 1 ? "s" : ""} need${pending.length > 1 ? "" : "s"} a human decision.` : "Nothing is waiting on you."}
      />

      <div className="overview-grid">
        <div className="overview-main">
          <section className="attention">
            <h2 className="section-title">
              <span>Needs approval</span>
              {pending.length ? <span className="count tone-pending">{pending.length}</span> : null}
            </h2>
            {reqs.loading ? (
              <Skeleton lines={3} />
            ) : pending.length === 0 ? (
              <Empty title="No pending requests" icon="check">Agents will appear here when they ask for access a policy routes to humans.</Empty>
            ) : (
              pending.map((r) => <PendingCard key={r.id} r={r} label={label} canApprove={canApprove} now={now} />)
            )}
          </section>

          <section>
            <h2 className="section-title">
              <span>Active access</span>
              {live.length ? <span className="count tone-active">{live.length}</span> : null}
            </h2>
            {reqs.loading ? (
              <Skeleton lines={2} />
            ) : live.length === 0 ? (
              <Empty title="No standing privilege" icon="active">No agent holds any authority right now.</Empty>
            ) : (
              <div className="stack">
                {live.map((r) => (
                  <a key={r.id} className="live-row" href={`#/console/requests/${r.id}`}>
                    <div className="live-row-top">
                      <span>
                        <strong>{label(r.agent_id)}</strong> <span className="muted">·</span> {actionTitle(r.action)} <span className="muted">on</span> <span className="mono">{r.resource_id}</span>
                      </span>
                      {r.state === "Active" ? <Countdown untilMs={r.valid_before * 1000} className="live-count" /> : <StateBadge state={r.state} />}
                    </div>
                    <WindowBar r={r} compact />
                    <div className="live-row-meta muted">
                      <span>uses {r.uses}/{r.max_uses}</span>
                      <span>{r.approvals.length ? `approved by ${r.approvals.map((a) => label(a.approver_id)).join(", ")}` : "approved by policy"}</span>
                    </div>
                  </a>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="section-title">
              <span>Recent denials</span>
              <span className="section-hint">Blocked escalation attempts are the product working.</span>
            </h2>
            {reqs.loading ? (
              <Skeleton lines={2} />
            ) : denials.length === 0 ? (
              <Empty title="No denied commands" icon="shield" />
            ) : (
              <div className="list">{denials.map((d) => <DenialRow key={`${d.request.id}-${d.event.seq}`} d={d} label={label} />)}</div>
            )}
          </section>

          <section>
            <h2 className="section-title">
              <span>Recently closed</span>
              <a className="section-link" href="#/console/requests">All requests <Icon name="arrow" size={12} /></a>
            </h2>
            {reqs.loading ? (
              <Skeleton lines={3} />
            ) : done.length === 0 ? (
              <Empty title="Nothing closed yet" icon="check" />
            ) : (
              <div className="list">
                {done.map((r) => (
                  <RequestLine key={r.id} r={r} label={label} right={<span className="closed-meta"><StateBadge state={r.state} /><span className="muted">{timeAgo(lastAt(r), now)}</span></span>} />
                ))}
              </div>
            )}
          </section>
        </div>

        <aside className="overview-side">
          <Panel title="System">
            <ul className="health">
              <li>
                <span className={cx("hdot", activeHosts.length && online === activeHosts.length ? "ok" : "idle")} />
                <span>Hosts</span>
                <span className="muted">
                  {!resources.data
                    ? "—"
                    : !activeHosts.length
                      ? "none active"
                      : online === activeHosts.length
                        ? `${online}/${activeHosts.length} online`
                        : lastHeartbeat
                          ? `last heartbeat ${timeAgo(lastHeartbeat, now)}`
                          : `${online}/${activeHosts.length} online`}
                </span>
              </li>
              {(ov.data?.environments ?? []).map((e) => (
                <li key={e.name}>
                  <span className={cx("hdot", e.ca_public_key ? "ok" : "warn")} />
                  <span>CA · {e.name}</span>
                  <span className="muted">{e.ca_public_key ? "MPC-derived" : "pending"}</span>
                </li>
              ))}
              <li>
                <span className={cx("hdot", ov.data ? "ok" : "warn")} />
                <span>Threshold signer</span>
                <span className="mono small">{ov.data?.config.mpc_contract ?? "—"}</span>
              </li>
              {relay.data && relay.data !== "unconfigured" ? (
                <li>
                  <span className={cx("hdot", relay.data === "ok" ? "ok" : "warn")} />
                  <span>Private relay</span>
                  <span className="muted">{relay.data === "ok" ? "connected" : "unreachable"}</span>
                </li>
              ) : null}
              <li>
                <span className="hdot ok" />
                <span>Policy engine</span>
                <span className="muted">{source.mode === "preview" ? "simulated" : "on-chain"}</span>
              </li>
            </ul>
          </Panel>
          <Panel title="Audit log">
            <div className="audit-mini">
              <div><span className="muted">sequence</span><span className="mono">#{ov.data?.audit_seq ?? "—"}</span></div>
              <div><span className="muted">chain head</span>{ov.data ? <Truncate text={ov.data.audit_head} head={12} tail={8} /> : "—"}</div>
              <div><span className="muted">requests</span><span className="mono">{ov.data?.request_count ?? "—"}</span></div>
              <div><span className="muted">revocations</span><span className="mono">{ov.data?.revocation_count ?? "—"}</span></div>
            </div>
            <p className="small muted">Every authorization event is hash-chained and anchored on NEAR. <a href="#/console/audit">Open audit</a></p>
          </Panel>
        </aside>
      </div>
    </div>
  );
}

function lastAt(r: AccessRequest) {
  return r.events.length ? r.events[r.events.length - 1].at_ms : r.created_at_ms;
}

function PendingCard({ r, label, canApprove, now }: { r: AccessRequest; label: (id: string) => string; canApprove: boolean; now: number }) {
  const left = r.approval_deadline_ms - now;
  return (
    <article className="pending-card">
      <div className="pending-top">
        <div className="pending-who">
          <span className="avatar">{label(r.agent_id).slice(0, 1)}</span>
          <div>
            <strong>{label(r.agent_id)}</strong>
            <div className="muted small">requested {timeAgo(r.created_at_ms, now)} · #{r.id}</div>
          </div>
        </div>
        <Badge tone="pending">Awaiting approval</Badge>
      </div>
      <div className="pending-what">
        <span className="pending-action">{actionTitle(r.action)}</span>
        <span className="muted">on</span>
        <span className="mono pending-res">{r.resource_id}</span>
        <Badge tone="muted" dot={false}>{r.environment}</Badge>
      </div>
      <p className="pending-why">“{r.reason}”</p>
      <div className="pending-facts">
        <span><Icon name="clock" size={13} /> {formatDuration(r.requested_duration_secs)} window</span>
        <span><Icon name="terminal" size={13} /> {r.max_uses === 1 ? "one use" : `${r.max_uses} uses`}</span>
        <span><Icon name="policies" size={13} /> {r.policy_id}</span>
        <span className={cx(left < 3 * 60_000 && "warn-text")}>decide within {Math.max(0, Math.ceil(left / 60_000))}m</span>
      </div>
      <div className="pending-actions">
        <a className="btn btn-primary" href={`#/console/requests/${r.id}`}>
          {canApprove ? "Review & decide" : "Review"} <Icon name="arrow" size={14} />
        </a>
      </div>
    </article>
  );
}
