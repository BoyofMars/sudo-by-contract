import { useState } from "react";
import { actionTitle, type AccessRequest } from "@sbc/client";
import { Countdown, Dialog, Empty, Field, PageHeader, Skeleton, StateBadge } from "../../components/ui.tsx";
import { WindowBar } from "../../components/domain.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useAction, useCanApprove, useLabels } from "../../lib/hooks.ts";

export function Active() {
  const { source } = useData();
  const label = useLabels();
  const canRevoke = useCanApprove();
  const q = useQuery((s) => s.requests({ states: ["Active", "Signing"], limit: 100 }), [], { interval: 4000 });
  const action = useAction();
  const [target, setTarget] = useState<AccessRequest | null>(null);
  const [reason, setReason] = useState("");

  return (
    <div className="page">
      <PageHeader title="Active access" subtitle="Every capability that exists right now. Each one dies on its own; you can kill it sooner." />
      {q.loading ? (
        <Skeleton lines={4} />
      ) : !q.data?.length ? (
        <Empty title="No standing privilege" icon="active">No agent holds any authority at this moment.</Empty>
      ) : (
        <div className="active-list">
          {q.data.map((r) => (
            <article key={r.id} className="active-card">
              <header>
                <div>
                  <a href={`#/console/requests/${r.id}`} className="active-title">
                    <strong>{label(r.agent_id)}</strong> · {actionTitle(r.action)}
                  </a>
                  <div className="muted small">
                    <span className="mono">{r.resource_id}</span> · #{r.id} · uses {r.uses}/{r.max_uses} · {r.approvals.length ? `approved by ${r.approvals.map((a) => label(a.approver_id)).join(", ")}` : "approved by policy"}
                  </div>
                </div>
                {r.state === "Active" ? <Countdown untilMs={r.valid_before * 1000} className="active-count" /> : <StateBadge state={r.state} />}
              </header>
              <WindowBar r={r} />
              {canRevoke ? (
                <footer>
                  <button className="btn btn-danger" disabled={action.busy} onClick={() => { setReason(""); setTarget(r); }}>
                    Revoke now
                  </button>
                </footer>
              ) : null}
            </article>
          ))}
        </div>
      )}
      <Dialog
        open={!!target}
        onClose={() => setTarget(null)}
        title={`Revoke #${target?.id ?? ""}`}
        footer={
          <>
            <button className="btn btn-secondary" onClick={() => setTarget(null)}>Cancel</button>
            <button
              className="btn btn-danger"
              onClick={async () => {
                const t = target!;
                setTarget(null);
                await action.run(() => source.revoke(t.id, reason.trim()), `Capability #${t.id} revoked`);
              }}
            >
              Revoke now
            </button>
          </>
        }
      >
        <p>The next command the agent sends is refused by the host gate. sshd rejects the certificate after the host's next revocation sync.</p>
        <Field label="Reason" hint="Recorded in the audit log.">
          <textarea className="textarea" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={280} />
        </Field>
      </Dialog>
    </div>
  );
}
