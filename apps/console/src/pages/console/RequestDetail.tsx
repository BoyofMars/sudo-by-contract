import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  actionCommand,
  actionTitle,
  b64decode,
  describePolicy,
  formatDuration,
  parseCertificateLine,
  riskOf,
  sshPublicKeyLine,
  type AccessRequest,
} from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, Command, CopyButton, Countdown, Dialog, Empty, ErrorNote, Field, FixtureTag, KV, PageHeader, Panel, Skeleton, StateBadge, Truncate, cx } from "../../components/ui.tsx";
import { PolicyChecks, Timeline, WindowBar } from "../../components/domain.tsx";
import { useData, useNow, useQuery } from "../../lib/data/context.tsx";
import { useAction, useCanApprove, useLabels } from "../../lib/hooks.ts";
import { verifyContext } from "../../lib/relay.ts";
import { clock, dateTime } from "../../lib/events.ts";
import { explorerBase } from "../../lib/config.ts";

type Stage = null | "submitting" | "recorded" | "waiting" | "issued";

export function RequestDetail({ id }: { id: number }) {
  const { source, identity } = useData();
  const label = useLabels();
  const canApprove = useCanApprove();
  const [stage, setStage] = useState<Stage>(null);
  const q = useQuery((s) => s.request(id), [id], { interval: stage ? 1500 : 4000 });
  const r = q.data;
  const ov = useQuery((s) => s.overview(), []);
  const policy = useQuery((s) => (r?.policy_id ? s.policy(r.policy_id, r.policy_version ?? undefined) : Promise.resolve(null)), [r?.policy_id, r?.policy_version]);
  const reports = useQuery((s) => s.gateReports({ request_id: id, limit: 50 }), [id], { interval: 10_000 });
  const action = useAction();
  const [dialog, setDialog] = useState<null | "approve" | "deny" | "revoke">(null);

  // a staged approval completes when the state leaves Signing
  useEffect(() => {
    if (!r || !stage) return;
    if (stage === "waiting" && r.state !== "Signing" && r.state !== "PendingApproval") setStage("issued");
    if (stage === "issued") {
      const t = setTimeout(() => setStage(null), 8000);
      return () => clearTimeout(t);
    }
  }, [r, stage]);

  if (q.loading) return <div className="page"><Skeleton lines={8} /></div>;
  if (!r)
    return (
      <div className="page">
        <PageHeader back={{ to: "/console/requests", label: "Requests" }} title={`Request #${id}`} subtitle={source.mode === "live" ? `Not on ${source.contractId}.` : "Not in this simulation."} />
        <Empty title={`Request #${id} not found`}>
          {source.mode === "live" ? (
            <>It may be from the simulation or another contract. <a href={`#/console/requests/${id}?preview=1`}>Open it in the simulation</a>.</>
          ) : (
            <>The simulation starts fresh in each tab. <a href="#/console?preview=0">Back to the live contract</a>.</>
          )}
        </Empty>
      </div>
    );

  const pending = r.state === "PendingApproval";
  const live = r.state === "Active" || r.state === "Signing";
  const mine = r.approvals.some((a) => a.approver_id === identity?.binding?.principal);
  const eligible = r.eligible_approvers.length === 0 || (identity?.binding && r.eligible_approvers.includes(identity.binding.principal));
  const risk = riskOf(r);
  const dur = r.granted_duration_secs || r.requested_duration_secs;

  const approve = async (maxDur?: number) => {
    setDialog(null);
    setStage("submitting");
    const res = await action.run(() => source.approve(r.id, maxDur));
    if (!res.ok) return setStage(null);
    const willSign = r.approvals.length + 1 >= r.required_approvals;
    setStage(willSign ? "waiting" : "recorded");
    q.reload();
  };

  return (
    <div className={cx("page", "request-page", (pending && canApprove) || (live && canApprove) ? "has-actionbar" : "")}>
      <PageHeader
        back={{ to: "/console/requests", label: "Requests" }}
        title={
          <span className="title-with-badge">
            {actionTitle(r.action)} <StateBadge state={r.state} />
          </span>
        }
        subtitle={
          <>
            <span className="mono">#{r.id}</span> · {label(r.agent_id)} · <span className="mono">{r.resource_id}</span> <FixtureTag id={r.resource_id} /> · {dateTime(r.created_at_ms)}
          </>
        }
        actions={
          canApprove ? (
            <div className="detail-actions hide-sm">
              {pending && !mine && eligible ? (
                <>
                  <button className="btn btn-secondary" onClick={() => setDialog("deny")} disabled={action.busy}>Deny</button>
                  <button className="btn btn-approve" onClick={() => setDialog("approve")} disabled={action.busy}>Approve {formatDuration(r.requested_duration_secs)}</button>
                </>
              ) : null}
              {live ? <button className="btn btn-danger" onClick={() => setDialog("revoke")} disabled={action.busy}>Revoke now</button> : null}
            </div>
          ) : null
        }
      />

      {pending ? (
        <div className="consequence">
          <Icon name="active" />
          <p>
            Approving lets <strong>{label(r.agent_id)}</strong> {actionTitle(r.action).replace(/^\w/, (c) => c.toLowerCase())} on <span className="mono">{r.resource_id}</span>{" "}
            <strong>{r.max_uses === 1 ? "once" : `up to ${r.max_uses} times`}</strong>, within a <strong>{formatDuration(r.requested_duration_secs)}</strong> window that starts when the certificate is issued.
            No shell, no other command, no other host.
          </p>
        </div>
      ) : null}

      {stage || r.state === "Signing" ? <IssueProgress r={r} stage={stage} /> : null}
      <ErrorNote error={action.error} />

      <div className="detail-grid">
        <div className="detail-main">
          <Panel title="Request" className="request-card">
            <dl className="facts">
              <Fact k="Who">
                <a href={`#/console/agents/${r.agent_id}`} className="strong-link">{label(r.agent_id)}</a> <span className="mono muted">{r.agent_id}</span>
              </Fact>
              <Fact k="What">
                {actionTitle(r.action)}
                <Command prompt="$" copy={false}>{actionCommand(r.action)}</Command>
              </Fact>
              <Fact k="Where">
                <a href={`#/console/resources/${r.resource_id}`} className="mono strong-link">{r.resource_id}</a> <Badge tone="muted" dot={false}>{r.environment}</Badge>
              </Fact>
              <Fact k="Window">
                {formatDuration(dur)}
                {r.granted_duration_secs && r.granted_duration_secs < r.requested_duration_secs ? <span className="muted"> (narrowed from {formatDuration(r.requested_duration_secs)})</span> : null}
              </Fact>
              <Fact k="Uses">
                {r.uses} of {r.max_uses} {r.max_uses === 1 ? <span className="muted">· single use</span> : null}
              </Fact>
              <Fact k="Policy">
                {r.policy_id ? (
                  <>
                    <a href={`#/console/policies/${r.policy_id}`} className="strong-link">{policy.data?.name ?? r.policy_id}</a> <span className="mono muted">v{r.policy_version}</span>
                    {policy.data ? <div className="fact-sub">{describePolicy(policy.data, { agent: label })}</div> : null}
                  </>
                ) : (
                  <span className="muted">no matching policy</span>
                )}
              </Fact>
              <Fact k="Risk">
                <Badge tone={risk.level === "low" ? "active" : risk.level === "limited" ? "pending" : "danger"}>{risk.level}</Badge> <span className="muted">{risk.why}</span>
              </Fact>
            </dl>
          </Panel>

          <Why r={r} />

          <Panel title="Policy evaluation" actions={r.policy_hash ? <span className="muted small">policy hash <Truncate text={r.policy_hash} head={8} tail={4} /></span> : null}>
            <PolicyChecks checks={r.checks} r={r} label={label} />
            {r.state_reason && ["Rejected", "Denied", "Failed", "Revoked"].includes(r.state) ? (
              <p className="reason-line"><Icon name="alert" size={14} /> {r.state_reason}</p>
            ) : null}
          </Panel>

          {r.valid_after > 0 || pending ? (
            <Panel title="Time window">
              <WindowBar r={r} />
            </Panel>
          ) : null}

          <HostActivity r={r} reports={reports.data ?? []} />

          <Panel title="Timeline" actions={<span className="muted small">select an event for technical detail</span>}>
            <Timeline events={[...r.events].reverse()} label={label} />
          </Panel>
        </div>

        <aside className="detail-side">
          <Panel title="Status">
            <div className="status-block">
              <StateBadge state={r.state} />
              {r.state === "Active" ? (
                <div className="status-remaining">
                  <Countdown untilMs={r.valid_before * 1000} className="big-count" />
                  <span className="muted">remaining · expires {clock(r.valid_before * 1000)}</span>
                </div>
              ) : null}
              {pending ? <ApprovalDeadline r={r} /> : null}
              {pending && canApprove && !mine && eligible ? (
                <div className="status-actions hide-sm">
                  <button className="btn btn-secondary" onClick={() => setDialog("deny")} disabled={action.busy}>Deny</button>
                  <button className="btn btn-approve" onClick={() => setDialog("approve")} disabled={action.busy}>Approve {formatDuration(r.requested_duration_secs)}</button>
                </div>
              ) : null}
            </div>
            <KV
              cols={1}
              items={[
                ["Approvals", r.required_approvals === 0 ? "policy (automatic)" : `${r.approvals.length} of ${r.required_approvals}${r.eligible_approvers.length ? ` · from ${r.eligible_approvers.map(label).join(", ")}` : ""}`],
                ...r.approvals.map((a) => [`✓ ${label(a.approver_id)}`, `${clock(a.at_ms)}${a.max_duration_secs ? ` · narrowed to ${formatDuration(a.max_duration_secs)}` : ""}`] as [string, string]),
                ["Denied attempts", r.denied_attempts ? <span className="danger-text">{r.denied_attempts}</span> : "0"],
                ...(r.revoked_by ? ([["Revoked by", label(r.revoked_by)]] as [string, string][]) : []),
              ]}
            />
          </Panel>

          {r.certificate ? <Certificate line={r.certificate} /> : null}

          <Panel title="Technical proof">
            <details className="proof">
              <summary>Verify this authorization</summary>
              <KV
                cols={1}
                items={[
                  ["Contract", <a className="mono" href={`${explorerBase(source.network)}/address/${source.contractId}`} target="_blank" rel="noreferrer">{source.contractId} <Icon name="external" size={12} /></a>],
                  ["Policy", r.policy_id ? <span className="mono">{r.policy_id}@v{r.policy_version}</span> : "—"],
                  ["Policy hash", r.policy_hash ? <Truncate text={r.policy_hash} head={14} tail={6} /> : "—"],
                  ["Context hash", r.context_hash ? <Truncate text={r.context_hash} head={14} tail={6} /> : "none"],
                  ["Audit events", <span className="mono">{r.events.map((e) => `#${e.seq}`).join(" ")}</span>],
                  ["Threshold signer", <span className="mono">{ov.data?.config.mpc_contract ?? "—"} · domain {ov.data?.config.mpc_domain_id ?? "—"} (Ed25519)</span>],
                  ["CA derivation path", <span className="mono">{ov.data?.environments.find((e) => e.name === r.environment)?.path ?? "—"}</span>],
                  ["Agent session key", <Truncate text={sshPublicKeyLine(b64decode(r.ssh_public_key))} head={22} tail={8} />],
                ]}
              />
              <p className="small muted">
                The certificate's CA key is derived by the NEAR MPC network for this contract's account. Only this contract can request signatures under it, and it only asks for certificate bodies it built from an approved request.
              </p>
            </details>
          </Panel>
        </aside>
      </div>

      {canApprove && (pending || live) ? (
        <div className="actionbar">
          {pending && !mine && eligible ? (
            <>
              <button className="btn btn-secondary btn-lg" onClick={() => setDialog("deny")} disabled={action.busy}>Deny</button>
              <button className="btn btn-approve btn-lg" onClick={() => setDialog("approve")} disabled={action.busy}>
                Approve {formatDuration(r.requested_duration_secs)}
              </button>
            </>
          ) : pending && mine ? (
            <span className="muted">You approved · waiting for {r.required_approvals - r.approvals.length} more</span>
          ) : null}
          {live ? <button className="btn btn-danger btn-lg" onClick={() => setDialog("revoke")} disabled={action.busy}>Revoke now</button> : null}
        </div>
      ) : null}

      <ApproveDialog open={dialog === "approve"} r={r} label={label} onClose={() => setDialog(null)} onConfirm={approve} />
      <ReasonDialog
        open={dialog === "deny"}
        title="Deny request"
        confirm="Deny request"
        tone="secondary"
        body={<p>The agent gets nothing. The denial and your reason are recorded in the audit log.</p>}
        onClose={() => setDialog(null)}
        onConfirm={async (reason) => {
          setDialog(null);
          await action.run(() => source.deny(r.id, reason), `Request #${r.id} denied`);
        }}
      />
      <ReasonDialog
        open={dialog === "revoke"}
        title="Revoke capability"
        confirm="Revoke now"
        tone="danger"
        body={
          <p>
            The host gate checks the contract before every command, so the very next command is refused. sshd also rejects the certificate once the host syncs its revocation list. Commands already running are not interrupted.
          </p>
        }
        onClose={() => setDialog(null)}
        onConfirm={async (reason) => {
          setDialog(null);
          await action.run(() => source.revoke(r.id, reason), `Capability #${r.id} revoked`);
        }}
      />
    </div>
  );
}

function Fact({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="fact">
      <dt>{k}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function ApprovalDeadline({ r }: { r: AccessRequest }) {
  const now = useNow(5000);
  const left = r.approval_deadline_ms - now;
  return <span className={cx("small", left < 3 * 60_000 ? "warn-text" : "muted")}>Decide within {Math.max(0, Math.ceil(left / 60_000))} min — then it lapses</span>;
}

function IssueProgress({ r, stage }: { r: AccessRequest; stage: Stage }) {
  const satisfied = r.approvals.length >= r.required_approvals;
  const steps: { label: string; state: "done" | "doing" | "todo" }[] = [
    { label: "Approval recorded on NEAR", state: stage === "submitting" ? "doing" : "done" },
    { label: r.required_approvals > 1 ? `Policy satisfied (${r.approvals.length}/${r.required_approvals} approvals)` : "Policy satisfied", state: satisfied ? "done" : stage === "submitting" ? "todo" : "doing" },
    { label: "Threshold signature from NEAR MPC", state: r.state === "Signing" ? "doing" : ["Active", "Exhausted", "Expired"].includes(r.state) ? "done" : "todo" },
    { label: "SSH certificate issued", state: r.certificate ? "done" : "todo" },
    { label: "Capability active on the host", state: r.state === "Active" ? "done" : "todo" },
  ];
  const caption =
    stage === "submitting"
      ? "Submitting approval…"
      : r.state === "Signing"
        ? "Requesting threshold signature… MPC nodes typically answer in 5–20 s."
        : stage === "recorded" && !satisfied
          ? "Approval recorded. Waiting for another approver."
          : r.state === "Active"
            ? "Certificate issued. The agent can act now — and only on this action."
            : r.state === "Failed"
              ? "Issuance failed. Nothing was issued; the request is closed."
              : "";
  return (
    <div className="issue" role="status" aria-live="polite">
      <ol className="issue-steps">
        {steps.map((s) => (
          <li key={s.label} className={`is-${s.state}`}>
            <span className="issue-dot">{s.state === "done" ? <Icon name="check" size={12} /> : null}</span>
            {s.label}
          </li>
        ))}
      </ol>
      {caption ? <p className="issue-caption">{caption}</p> : null}
    </div>
  );
}

function Why({ r }: { r: AccessRequest }) {
  const ctx = useQuery((s) => (r.context_hash ? s.context(r.context_hash) : Promise.resolve(null)), [r.context_hash]);
  const [verified, setVerified] = useState<boolean | null>(null);
  useEffect(() => {
    setVerified(null);
    if (ctx.data && r.context_hash) verifyContext(ctx.data, r.context_hash).then(setVerified);
  }, [ctx.data, r.context_hash]);
  return (
    <Panel title="Why">
      <blockquote className="why-quote">{r.reason || <span className="muted">No reason given.</span>}</blockquote>
      <p className="small muted why-note">Stated by the agent. Explanations are shown to people; they never change what policy allows.</p>
      {r.context_hash ? (
        ctx.loading ? (
          <Skeleton lines={2} />
        ) : ctx.data ? (
          <div className="context">
            <div className="context-head">
              <span>Private context</span>
              {verified === true ? (
                <Badge tone="active">matches on-chain hash</Badge>
              ) : verified === false ? (
                <Badge tone="danger">does not match on-chain hash</Badge>
              ) : (
                <Badge tone="muted">verifying…</Badge>
              )}
            </div>
            {ctx.data.document.rationale && ctx.data.document.rationale !== r.reason ? <p className="context-rationale">{ctx.data.document.rationale}</p> : null}
            {ctx.data.document.evidence?.length ? (
              <dl className="evidence">
                {ctx.data.document.evidence.map((e, i) => (
                  <div key={i}>
                    <dt>{e.label}</dt>
                    <dd className="mono">{e.value}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
            {ctx.data.document.links?.length ? (
              <div className="context-links">
                {ctx.data.document.links.map((l) => (
                  <a key={l.url} href={l.url} target="_blank" rel="noreferrer noopener">
                    {l.label} <Icon name="external" size={12} />
                  </a>
                ))}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="quiet-note">
            <Icon name="dot" size={12} /> Private context unavailable (hash committed on-chain: <Truncate text={r.context_hash} head={10} tail={4} />).
          </p>
        )
      ) : null}
    </Panel>
  );
}

function HostActivity({ r, reports }: { r: AccessRequest; reports: import("../../lib/relay.ts").GateReport[] }) {
  const rows = useMemo(() => {
    if (reports.length) return reports.map((x) => ({ at: x.at_ms, ok: x.decision === "allowed", cmd: x.redacted_command, why: x.decision === "allowed" ? `exit ${x.exit_code ?? "—"}${x.duration_ms ? ` · ${x.duration_ms} ms` : ""}` : x.code.replace(/_/g, " ") }));
    return r.events
      .filter((e) => e.kind === "command_allowed" || e.kind === "command_denied")
      .map((e) => {
        const ok = e.kind === "command_allowed";
        const m = /^(?:([a-z_]+): attempted )?(\S+)/.exec(e.detail);
        const raw = m?.[2] ?? e.detail;
        const cmd = raw.startsWith("`") ? raw.replace(/`/g, "") + " …" : actionCommand(raw);
        return { at: e.at_ms, ok, cmd, why: ok ? "allowed" : (m?.[1] ?? "denied").replace(/_/g, " ") };
      })
      .reverse();
  }, [r, reports]);
  if (!rows.length) return null;
  return (
    <Panel title="Activity on the host" actions={<span className="muted small">{reports.length ? "redacted command text from the gate" : "from on-chain events"}</span>}>
      <ul className="activity">
        {rows.map((x, i) => (
          <li key={i} className={x.ok ? "ok" : "no"}>
            <span className="act-icon">{x.ok ? <Icon name="check" size={13} /> : <Icon name="x" size={13} />}</span>
            <code className="mono">{x.cmd}</code>
            <span className="act-why">{x.why}</span>
            <span className="act-time mono muted">{clock(x.at)}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Certificate({ line }: { line: string }) {
  const c = useMemo(() => {
    try {
      return parseCertificateLine(line);
    } catch {
      return null;
    }
  }, [line]);
  if (!c) return null;
  return (
    <Panel title="Credential" actions={<CopyButton text={line} label="Copy certificate" />}>
      <KV
        cols={1}
        items={[
          ["Type", "OpenSSH user certificate (Ed25519)"],
          ["Serial", <span className="mono">{c.serial.toString()}</span>],
          ["Key ID", <span className="mono wrap">{c.keyId}</span>],
          ["Principals", <span className="mono">{c.principals.join(", ")}</span>],
          ["Valid", <span className="mono">{clock(c.validAfter * 1000)} → {clock(c.validBefore * 1000)}</span>],
          ["force-command", <span className="mono">{c.criticalOptions["force-command"] ?? "—"}</span>],
          ["Extensions", c.extensions.length ? <span className="mono">{c.extensions.join(", ")}</span> : <span>(none) <span className="muted">— no PTY, no forwarding</span></span>],
          ["Signing CA", <Truncate text={sshPublicKeyLine(c.caPublicKey)} head={22} tail={8} />],
        ]}
      />
    </Panel>
  );
}

function ApproveDialog({ open, r, label, onClose, onConfirm }: { open: boolean; r: AccessRequest; label: (id: string) => string; onClose: () => void; onConfirm: (maxDur?: number) => void }) {
  const options = [60, 120, 300, 600, 900, 1800, 3600].filter((s) => s < r.requested_duration_secs);
  const [dur, setDur] = useState(r.requested_duration_secs);
  const simulated = useData().source.mode === "preview";
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Approve access"
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-approve" onClick={() => onConfirm(dur < r.requested_duration_secs ? dur : undefined)}>
            Approve {formatDuration(dur)}
          </button>
        </>
      }
    >
      <dl className="approve-summary">
        <div><dt>Who</dt><dd>{label(r.agent_id)}</dd></div>
        <div><dt>What</dt><dd>{actionTitle(r.action)}</dd></div>
        <div><dt>Where</dt><dd className="mono">{r.resource_id}</dd></div>
        <div><dt>Uses</dt><dd>{r.max_uses === 1 ? "1 — single use" : r.max_uses}</dd></div>
      </dl>
      <Field label="Window" hint="You can narrow the window, never widen it. It starts when the certificate is issued.">
        <select className="select" value={dur} onChange={(e) => setDur(Number(e.target.value))}>
          <option value={r.requested_duration_secs}>{formatDuration(r.requested_duration_secs)} (requested)</option>
          {options.reverse().map((s) => (
            <option key={s} value={s}>{formatDuration(s)}</option>
          ))}
        </select>
      </Field>
      {simulated ? (
        <p className="small muted">
          Simulation: nothing is sent anywhere. On a live contract your approval is signed by this device's key and recorded on NEAR, and if it completes the policy the MPC network signs a certificate valid only for <span className="mono">sbc-{r.resource_id}</span>.
        </p>
      ) : (
        <p className="small muted">
          Your approval is signed by this device's key and recorded on NEAR. If it completes the policy, the contract immediately asks the MPC network to sign a certificate valid only for <span className="mono">sbc-{r.resource_id}</span>, forced through the host gate.
        </p>
      )}
    </Dialog>
  );
}

function ReasonDialog({ open, title, confirm, tone, body, onClose, onConfirm }: { open: boolean; title: string; confirm: string; tone: "danger" | "secondary"; body: ReactNode; onClose: () => void; onConfirm: (reason: string) => void }) {
  const [reason, setReason] = useState("");
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className={cx("btn", tone === "danger" ? "btn-danger" : "btn-primary")} onClick={() => onConfirm(reason.trim())}>
            {confirm}
          </button>
        </>
      }
    >
      {body}
      <Field label="Reason" hint="Recorded publicly in the audit log. Keep secrets out of it.">
        <textarea className="textarea" rows={3} maxLength={280} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. rolled back instead" />
      </Field>
    </Dialog>
  );
}
