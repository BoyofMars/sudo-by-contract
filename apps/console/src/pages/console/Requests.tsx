import { useMemo, useState } from "react";
import { actionTitle, formatDuration, LIVE_STATES, type RequestState } from "@sbc/client";
import { Empty, FixtureTag, PageHeader, Segmented, Skeleton, StateBadge } from "../../components/ui.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useLabels } from "../../lib/hooks.ts";
import { dateTime } from "../../lib/events.ts";

type Filter = "all" | "pending" | "live" | "closed";
const CLOSED: RequestState[] = ["Exhausted", "Expired", "Revoked", "Denied", "Rejected", "ApprovalExpired", "Failed", "Cancelled"];

export function Requests({ query }: { query: URLSearchParams }) {
  const label = useLabels();
  const { source, bump } = useData();
  const [showFixtures, setShowFixtures] = useState(source.showFixtures !== false);
  const fixtures = useQuery((s) => (s.fixtureSummary ? s.fixtureSummary() : Promise.resolve(null)), [], { interval: 60_000 });
  const [filter, setFilter] = useState<Filter>((query.get("filter") as Filter) || "all");
  const [agent, setAgent] = useState(query.get("agent") ?? "");
  const [resource, setResource] = useState(query.get("resource") ?? "");
  const reqs = useQuery((s) => s.requests({ limit: 100, agent_id: agent || undefined, resource_id: resource || undefined }), [agent, resource], { interval: 6000 });
  const agents = useQuery((s) => s.agents(), []);
  const resources = useQuery((s) => s.resources(), []);

  const rows = useMemo(() => {
    const all = reqs.data ?? [];
    if (filter === "pending") return all.filter((r) => r.state === "PendingApproval");
    if (filter === "live") return all.filter((r) => LIVE_STATES.includes(r.state));
    if (filter === "closed") return all.filter((r) => CLOSED.includes(r.state));
    return all;
  }, [reqs.data, filter]);

  return (
    <div className="page">
      <PageHeader title="Requests" subtitle="Every capability an agent has asked for, and what policy and people decided." />
      <div className="filters">
        <Segmented<Filter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All" },
            { value: "pending", label: "Pending" },
            { value: "live", label: "Active" },
            { value: "closed", label: "Closed" },
          ]}
        />
        <select className="select" value={agent} onChange={(e) => setAgent(e.target.value)} aria-label="Filter by agent">
          <option value="">All agents</option>
          {(agents.data ?? []).map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
        </select>
        <select className="select" value={resource} onChange={(e) => setResource(e.target.value)} aria-label="Filter by resource">
          <option value="">All resources</option>
          {(resources.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
        </select>
        {source.setShowFixtures && fixtures.data?.requests ? (
          <label className="check-inline small">
            <input
              type="checkbox"
              checked={showFixtures}
              onChange={(e) => {
                source.setShowFixtures?.(e.target.checked);
                setShowFixtures(e.target.checked);
                bump();
              }}
            />
            Include e2e test runs
          </label>
        ) : null}
      </div>

      {reqs.loading ? (
        <Skeleton lines={6} />
      ) : rows.length === 0 ? (
        <Empty title="No requests match">Try another filter.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Agent</th>
                <th>Capability</th>
                <th>Resource</th>
                <th className="hide-md">Window</th>
                <th>State</th>
                <th className="hide-md">Requested</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} onClick={() => (window.location.hash = `#/console/requests/${r.id}`)} className="clickable">
                  <td className="mono muted">
                    <a href={`#/console/requests/${r.id}`}>#{r.id}</a>
                  </td>
                  <td className="nowrap">{label(r.agent_id)}</td>
                  <td>
                    {actionTitle(r.action)}
                    <div className="cell-sub">{r.reason}</div>
                  </td>
                  <td className="mono nowrap">{r.resource_id} <FixtureTag id={r.resource_id} /></td>
                  <td className="hide-md mono">
                    {formatDuration(r.granted_duration_secs || r.requested_duration_secs)} · {r.uses}/{r.max_uses}
                  </td>
                  <td><StateBadge state={r.state} /></td>
                  <td className="hide-md muted">{dateTime(r.created_at_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
