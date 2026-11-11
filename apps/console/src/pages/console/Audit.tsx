import { useMemo, useState } from "react";
import { actionTitle } from "@sbc/client";
import { Badge, Chips, Empty, FixtureTag, PageHeader, Panel, Skeleton, Truncate, cx } from "../../components/ui.tsx";
import { Icon } from "../../components/Icon.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useLabels } from "../../lib/hooks.ts";
import { explorerBase } from "../../lib/config.ts";
import { EVENT_GROUPS, dateTime, eventTitle, groupOf, parseDenial } from "../../lib/events.ts";

const SHOWN = 300;

export function Audit() {
  const { source } = useData();
  const label = useLabels();
  const reqs = useQuery((s) => s.requests({ limit: 100 }), [], { interval: 10_000 });
  const ov = useQuery((s) => s.overview(), [], { interval: 15_000 });
  const reports = useQuery((s) => s.gateReports({ limit: 100 }), [], { interval: 15_000 });
  const [kinds, setKinds] = useState<string[]>([]);
  const [text, setText] = useState("");
  const [open, setOpen] = useState<number | null>(null);

  const all = useMemo(() => (reqs.data ?? []).flatMap((r) => r.events.map((e) => ({ r, e }))).sort((a, b) => b.e.seq - a.e.seq), [reqs.data]);
  const rows = useMemo(() => {
    const allowed = new Set(EVENT_GROUPS.filter((g) => kinds.includes(g.value)).flatMap((g) => g.kinds));
    const t = text.trim().toLowerCase();
    return all.filter(({ r, e }) => (!kinds.length || allowed.has(e.kind)) && (!t || `${r.id} ${r.agent_id} ${r.resource_id} ${r.action} ${e.actor} ${e.detail} ${e.kind}`.toLowerCase().includes(t)));
  }, [all, kinds, text]);
  const head = ov.data?.audit_seq ?? 0;
  const newestShown = all[0]?.e.seq ?? 0;

  return (
    <div className="page">
      <PageHeader title="Audit" subtitle="Every authorization event, newest first. Denials are first-class records." />
      <div className="chain-head">
        <div>
          <span className="muted small">Hash-chained audit log anchored on NEAR</span>
          <div className="chain-row">
            <span className="mono">seq #{ov.data?.audit_seq ?? "—"}</span>
            <span className="muted">head</span>
            {ov.data ? <Truncate text={ov.data.audit_head} head={20} tail={10} /> : "—"}
          </div>
        </div>
        <p className="small muted">
          Each event is emitted as a NEP-297 log by the contract and folded into <span className="mono">head = sha256(head ‖ event)</span>. Off-chain copies can be checked against it; terminal output is never recorded.
        </p>
      </div>

      <div className="filters filters-wrap">
        <input className="input" placeholder="Filter by agent, resource, action, detail…" value={text} onChange={(e) => setText(e.target.value)} />
        <Chips options={EVENT_GROUPS.map((g) => ({ value: g.value, label: g.label }))} value={kinds} onChange={setKinds} />
      </div>

      {!reqs.loading && all.length ? (
        <p className="small muted audit-scope">
          Showing {Math.min(rows.length, SHOWN)} of {all.length} events attached to capability requests.
          {source.mode === "live" && head > newestShown ? (
            <>
              {" "}Events not tied to a request (identity, key and policy changes; up to #{head}) are in the contract's transaction logs:{" "}
              <a href={`${explorerBase(source.network)}/address/${source.contractId}`} target="_blank" rel="noreferrer">open on the explorer <Icon name="external" size={11} /></a>.
            </>
          ) : null}
        </p>
      ) : null}

      {reqs.loading ? (
        <Skeleton lines={8} />
      ) : !rows.length ? (
        <Empty title="No events match" />
      ) : (
        <div className="audit-table">
          {rows.slice(0, SHOWN).map(({ r, e }) => {
            const t = eventTitle(e, label);
            const denial = e.kind === "command_denied" ? parseDenial(r, e, reports.data ?? []) : null;
            const expanded = open === e.seq;
            return (
              <div key={e.seq} className={cx("audit-row", `tone-${t.tone}`, expanded && "open")}>
                <button className="audit-main" onClick={() => setOpen(expanded ? null : e.seq)} aria-expanded={expanded}>
                  <span className="mono muted audit-seq">#{e.seq}</span>
                  <span className="audit-kind mono">{groupOf(e.kind)}</span>
                  <span className="audit-text">
                    {denial ? (
                      <>
                        <strong>{label(r.agent_id)}</strong> attempted <code className="mono inline-cmd">{denial.attempted}</code> — <span className="danger-text">{denial.why}</span>
                      </>
                    ) : (
                      <>
                        {t.title}{" "}
                        <span className="muted">
                          · {t.title.includes(label(r.agent_id)) ? "" : `${label(r.agent_id)} · `}
                          {actionTitle(r.action)} on <span className="mono">{r.resource_id}</span>
                        </span>
                      </>
                    )}{" "}
                    <FixtureTag id={r.resource_id} />
                  </span>
                  <span className="audit-time muted">{dateTime(e.at_ms)}</span>
                </button>
                {expanded ? (
                  <dl className="tl-tech">
                    <div><dt>request</dt><dd><a className="mono" href={`#/console/requests/${r.id}`}>#{r.id}</a></dd></div>
                    <div><dt>event</dt><dd className="mono">{e.kind} · seq {e.seq}</dd></div>
                    <div><dt>actor</dt><dd className="mono">{e.actor}</dd></div>
                    <div><dt>detail</dt><dd className="mono wrap">{e.detail}</dd></div>
                    <div><dt>time</dt><dd className="mono">{new Date(e.at_ms).toISOString()}</dd></div>
                  </dl>
                ) : null}
              </div>
            );
          })}
        </div>
      )}

      {reports.data?.length ? (
        <Panel title="Gate reports" actions={<span className="muted small">private relay · redacted at the host</span>} flush>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>When</th><th>Resource</th><th>Command (redacted)</th><th>Decision</th><th className="hide-md">sha256</th></tr>
              </thead>
              <tbody>
                {reports.data.slice(0, 50).map((x, i) => (
                  <tr key={i}>
                    <td className="muted">{dateTime(x.at_ms)}</td>
                    <td className="mono">{x.resource_id}</td>
                    <td><code className="mono inline-cmd">{x.redacted_command}</code></td>
                    <td><Badge tone={x.decision === "allowed" ? "active" : "danger"}>{x.decision === "allowed" ? `allowed · exit ${x.exit_code ?? "—"}` : x.code.replace(/_/g, " ")}</Badge></td>
                    <td className="hide-md"><Truncate text={x.command_sha256} head={8} tail={4} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
