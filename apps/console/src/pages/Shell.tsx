import { useEffect, useState } from "react";
import { Icon, Mark } from "../components/Icon.tsx";
import { cx } from "../components/ui.tsx";
import { useData, useQuery } from "../lib/data/context.tsx";
import { LIVE_CONTRACT } from "../lib/config.ts";
import { match } from "../lib/router.tsx";
import { useTheme } from "../lib/hooks.ts";
import { Overview } from "./console/Overview.tsx";
import { Requests } from "./console/Requests.tsx";
import { RequestDetail } from "./console/RequestDetail.tsx";
import { Active } from "./console/Active.tsx";
import { Agents, AgentDetail } from "./console/Agents.tsx";
import { Resources, ResourceDetail, AddResource } from "./console/Resources.tsx";
import { Policies } from "./console/Policies.tsx";
import { PolicyBuilder } from "./console/PolicyBuilder.tsx";
import { Audit } from "./console/Audit.tsx";
import { Settings } from "./console/Settings.tsx";

const NAV = [
  { to: "/console", label: "Overview", icon: "overview", exact: true },
  { to: "/console/requests", label: "Requests", icon: "requests" },
  { to: "/console/active", label: "Active access", icon: "active" },
  { to: "/console/agents", label: "Agents", icon: "agents" },
  { to: "/console/resources", label: "Resources", icon: "resources" },
  { to: "/console/policies", label: "Policies", icon: "policies" },
  { to: "/console/audit", label: "Audit", icon: "audit" },
  { to: "/console/settings", label: "Settings", icon: "settings" },
];

const MOBILE = ["/console", "/console/requests", "/console/active", "/console/audit"];

export function Shell({ path, query }: { path: string; query: URLSearchParams }) {
  const { source, setClockOffset, identity, bump } = useData();
  const [theme, setTheme] = useTheme();
  const [moreOpen, setMoreOpen] = useState(false);
  const [showFixtures, setShowFixtures] = useState(!!source.showFixtures);
  const ov = useQuery((s) => s.overview(), [], { interval: 15_000 });
  const fixtures = useQuery((s) => (s.fixtureSummary ? s.fixtureSummary() : Promise.resolve(null)), [], { interval: 60_000 });
  const fx = fixtures.data;
  const fixtureTotal = fx ? fx.resources + fx.approvers + fx.agents + fx.requests : 0;
  const toggleFixtures = () => {
    const next = !showFixtures;
    source.setShowFixtures?.(next);
    setShowFixtures(next);
    bump();
  };
  const pending = useQuery((s) => s.requests({ states: ["PendingApproval"], limit: 20 }), [], { interval: 10_000 });
  useEffect(() => {
    if (ov.data) setClockOffset(ov.data.now_ms - Date.now());
  }, [ov.data, setClockOffset]);
  useEffect(() => {
    setMoreOpen(false);
    window.scrollTo(0, 0);
  }, [path]);

  const pendingCount = pending.data?.length ?? 0;
  const active = (to: string, exact?: boolean) => (exact ? path === to : path === to || path.startsWith(to + "/"));

  let page;
  let m: Record<string, string> | null;
  if (path === "/console") page = <Overview />;
  else if (path === "/console/requests") page = <Requests query={query} />;
  else if ((m = match("/console/requests/:id", path))) page = <RequestDetail id={Number(m.id)} />;
  else if (path === "/console/active") page = <Active />;
  else if (path === "/console/agents") page = <Agents />;
  else if ((m = match("/console/agents/:id", path))) page = <AgentDetail id={m.id} />;
  else if (path === "/console/resources") page = <Resources />;
  else if (path === "/console/resources/new") page = <AddResource />;
  else if ((m = match("/console/resources/:id", path))) page = <ResourceDetail id={m.id} />;
  else if (path === "/console/policies") page = <Policies />;
  else if (path === "/console/policies/new") page = <PolicyBuilder template={query.get("template")} />;
  else if ((m = match("/console/policies/:id", path))) page = <PolicyBuilder id={m.id} />;
  else if (path === "/console/audit") page = <Audit />;
  else if (path === "/console/settings") page = <Settings />;
  else page = <Overview />;

  const who = identity?.binding ? `${identity.binding.principal} · ${identity.binding.role.toLowerCase()}` : identity?.publicKey ? "key not enrolled" : "read-only";
  const readOnly = !identity?.binding;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#/">
          <Mark size={20} />
          <span>Sudo by Contract</span>
        </a>
        <nav className="nav">
          {NAV.map((n) => (
            <a key={n.to} href={"#" + n.to} className={cx("nav-item", active(n.to, n.exact) && "on")}>
              <Icon name={n.icon} />
              <span>{n.label}</span>
              {n.to === "/console/requests" && pendingCount > 0 ? <span className="nav-count">{pendingCount}</span> : null}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="conn">
            <span className={cx("conn-dot", source.mode === "preview" ? "preview" : ov.error ? "down" : "up")} />
            <div>
              <div className="mono conn-id" title={source.contractId}>{source.mode === "preview" ? "preview (simulated)" : source.contractId}</div>
              <div className="muted conn-net">{source.mode === "preview" ? "no network" : `NEAR ${source.network}`}</div>
            </div>
          </div>
          <button className="btn btn-ghost btn-xs" onClick={() => setTheme(theme === "dark" ? "light" : theme === "light" ? "system" : "dark")} title={`Theme: ${theme}`}>
            <Icon name={theme === "dark" ? "moon" : "sun"} size={14} /> <span>{theme}</span>
          </button>
        </div>
      </aside>

      <div className="main">
        {source.mode === "preview" ? (
          <div className="preview-banner" role="note">
            <strong>Simulation.</strong> <span className="fx-long">Nothing here touches a network: approve, deny and revoke freely.</span>{" "}
            {LIVE_CONTRACT ? <a href={`#/console?contract=${LIVE_CONTRACT}`}>Back to the live contract</a> : <a href="#/console/settings">Connect a contract</a>}
          </div>
        ) : (
          <div className="live-banner" role="note">
            <span className="live-chip"><span className="live-dot" aria-hidden /> Live</span>
            <span className="lb-text">
              <span className="fx-long">{readOnly ? `Read-only view of ${source.contractId} on NEAR ${source.network}. Every row is read from the chain.` : `Every row is read from ${source.contractId} on NEAR ${source.network}.`}</span>
              <span className="fx-short">NEAR {source.network}{readOnly ? " · read-only" : ""}</span>
            </span>
            {fx && fixtureTotal > 0 ? (
              <span
                className="lb-fx"
                title={`Test fixtures from the live end-to-end run (named e2e-…): ${[
                  fx.resources ? `${fx.resources} host${fx.resources > 1 ? "s" : ""}` : "",
                  fx.approvers ? `${fx.approvers} approver${fx.approvers > 1 ? "s" : ""}` : "",
                  fx.agents ? `${fx.agents} agent${fx.agents > 1 ? "s" : ""}` : "",
                  fx.requests ? `${fx.requests} request${fx.requests > 1 ? "s" : ""}` : "",
                ].filter(Boolean).join(", ")}`}
              >
                <span className="fixture-tag mono">e2e</span>
                <span>{showFixtures ? "shown" : `${fixtureTotal} hidden`}</span>
                <button type="button" className="btn btn-ghost btn-xs" onClick={toggleFixtures}>{showFixtures ? "Hide" : "Show"}</button>
              </span>
            ) : null}
            {readOnly ? (
              <a className="btn btn-secondary btn-xs lb-sim" href="#/console?preview=1">
                <span className="fx-long">Try the simulation</span>
                <span className="fx-short">Simulation</span>
              </a>
            ) : null}
          </div>
        )}
        <header className="topbar">
          <a className="brand brand-mobile" href="#/">
            <Mark size={18} />
          </a>
          <div className="topbar-conn">
            <span className={cx("conn-dot", source.mode === "preview" ? "preview" : ov.error ? "down" : "up")} />
            <span className="mono">{source.mode === "preview" ? "preview" : source.contractId}</span>
            {ov.data ? <span className="muted hide-sm">· audit #{ov.data.audit_seq}</span> : null}
          </div>
          <div className="topbar-id">
            <Icon name="key" size={14} />
            <span>{who}</span>
          </div>
        </header>
        <main className="content">{page}</main>
      </div>

      <nav className="tabbar" aria-label="Primary">
        {NAV.filter((n) => MOBILE.includes(n.to)).map((n) => (
          <a key={n.to} href={"#" + n.to} className={cx("tab", active(n.to, n.exact) && "on")}>
            <Icon name={n.icon} size={18} />
            <span>{n.label === "Active access" ? "Active" : n.label}</span>
            {n.to === "/console/requests" && pendingCount > 0 ? <span className="tab-count">{pendingCount}</span> : null}
          </a>
        ))}
        <button className={cx("tab", moreOpen && "on")} onClick={() => setMoreOpen((v) => !v)} aria-expanded={moreOpen}>
          <Icon name="menu" size={18} />
          <span>More</span>
        </button>
      </nav>
      {moreOpen ? (
        <div className="sheet" onClick={() => setMoreOpen(false)}>
          <div className="sheet-body" onClick={(e) => e.stopPropagation()}>
            {NAV.filter((n) => !MOBILE.includes(n.to)).map((n) => (
              <a key={n.to} href={"#" + n.to} className="sheet-item">
                <Icon name={n.icon} /> {n.label}
              </a>
            ))}
            <button className="sheet-item" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
              <Icon name={theme === "dark" ? "sun" : "moon"} /> {theme === "dark" ? "Light theme" : "Dark theme"}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
