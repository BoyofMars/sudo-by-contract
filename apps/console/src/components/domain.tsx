// Domain components: the time window, policy evaluation, timelines, rows.

import { useState, type ReactNode } from "react";
import { actionCommand, actionTitle, formatCountdown, formatDuration, type AccessRequest, type Check, type RequestEvent } from "@sbc/client";
import { Icon } from "./Icon.tsx";
import { cx, StateBadge, Badge } from "./ui.tsx";
import { useNow } from "../lib/data/context.tsx";
import { CODE_WHY, clock, eventTitle, timeAgo, type Denial } from "../lib/events.ts";

/**
 * The product's core visual: privilege exists inside a bounded window.
 * Brackets mark the window; a hairline marks "now". Calm, no ticking drama.
 */
export function WindowBar({ r, compact }: { r: AccessRequest; compact?: boolean }) {
  const now = useNow(1000);
  const issued = r.valid_after > 0;
  if (!issued) {
    const dur = r.granted_duration_secs || r.requested_duration_secs;
    return (
      <div className={cx("window", "window-pending", compact && "window-compact")}>
        <div className="window-track">
          <div className="window-span dashed" style={{ left: "8%", width: "84%" }}>
            <span className="br br-l" />
            <span className="br br-r" />
          </div>
        </div>
        {compact ? null : (
          <div className="window-legend">
            <span>starts when the certificate is issued</span>
            <span className="mono">{formatDuration(dur)} window</span>
          </div>
        )}
      </div>
    );
  }
  // the agent can use it from issuance (valid_after includes 60s skew allowance)
  const start = (r.valid_after + 60) * 1000;
  const end = r.valid_before * 1000;
  const dur = Math.max(1, end - start);
  const pad = dur * 0.08;
  const lo = start - pad;
  const hi = end + pad;
  const pct = (t: number) => `${(Math.min(hi, Math.max(lo, t)) - lo) / (hi - lo) * 100}%`;
  const live = r.state === "Active" && now < end;
  const closedAt = r.state === "Active" ? end : lastEventAt(r) ?? end;
  const cut = Math.min(end, Math.max(start, live ? now : closedAt));
  return (
    <div className={cx("window", live ? "window-live" : "window-closed", compact && "window-compact")}>
      <div className="window-track">
        <div className="window-span" style={{ left: pct(start), width: `calc(${pct(end)} - ${pct(start)})` }}>
          <span className="br br-l" />
          <span className="br br-r" />
          <span className="window-used" style={{ width: `${((cut - start) / dur) * 100}%` }} />
        </div>
        {live ? <span className="window-now" style={{ left: pct(now) }} /> : null}
      </div>
      {compact ? null : (
        <div className="window-legend">
          <span className="mono">{clock(start)}</span>
          <span className={cx("window-mid", live && "live")}>
            {live ? <>{formatCountdown(end - now)} remaining</> : r.state === "Active" ? "window elapsed" : `closed · ${closedLabel(r)}`}
          </span>
          <span className="mono">{clock(end)}</span>
        </div>
      )}
    </div>
  );
}

function lastEventAt(r: AccessRequest): number | null {
  const e = [...r.events].reverse().find((x) => ["authorization_used", "authorization_revoked", "authorization_released", "authorization_expired"].includes(x.kind));
  return e ? e.at_ms : null;
}

function closedLabel(r: AccessRequest) {
  switch (r.state) {
    case "Exhausted": return "used up";
    case "Revoked": return "revoked";
    case "Expired": return "expired";
    case "Cancelled": return "released";
    default: return r.state.toLowerCase();
  }
}

const CHECK_LABEL: Record<string, string> = {
  identity: "Identity",
  environment: "Environment",
  resource: "Resource",
  action: "Action",
  target: "Target",
  duration: "Maximum duration",
  uses: "Uses",
  schedule: "Schedule",
  source: "Source address",
  approval: "Human approval",
  deny: "Explicit deny",
};

export function PolicyChecks({ checks, r, label = (x) => x }: { checks: Check[]; r?: AccessRequest; label?: (id: string) => string }) {
  return (
    <ul className="checks">
      {checks.map((c, i) => {
        let state: "ok" | "fail" | "wait" = c.ok ? "ok" : "fail";
        let detail: ReactNode = c.detail;
        if (c.name === "approval" && r) {
          if (r.required_approvals === 0) {
            detail = "approved by policy";
          } else if (r.state === "PendingApproval") {
            state = "wait";
            detail = `${r.approvals.length} of ${r.required_approvals} — waiting`;
          } else if (r.approvals.length >= r.required_approvals) {
            detail = `approved by ${r.approvals.map((a) => label(a.approver_id)).join(", ")}`;
          } else if (["Denied", "ApprovalExpired"].includes(r.state)) {
            state = "fail";
            detail = r.state === "Denied" ? "denied" : "not approved in time";
          }
        }
        return (
          <li key={i} className={cx("check", `check-${state}`)}>
            <span className="check-icon">{state === "ok" ? <Icon name="check" size={14} /> : state === "fail" ? <Icon name="x" size={14} /> : <Icon name="circle" size={14} />}</span>
            <span className="check-name">{CHECK_LABEL[c.name] ?? c.name}</span>
            <span className="check-detail">{detail}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function Timeline({ events, label = (x) => x }: { events: RequestEvent[]; label?: (id: string) => string }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <ol className="timeline">
      {events.map((e) => {
        const t = eventTitle(e, label);
        const expanded = open === e.seq;
        return (
          <li key={e.seq} className={cx("tl-item", `tone-${t.tone}`)}>
            <span className="tl-dot" />
            <button className="tl-main" onClick={() => setOpen(expanded ? null : e.seq)} aria-expanded={expanded}>
              <span className="tl-title">{t.title}</span>
              <span className="tl-time mono">{clock(e.at_ms)}</span>
            </button>
            {e.detail ? <div className="tl-detail">{humanDetail(e)}</div> : null}
            {expanded ? (
              <dl className="tl-tech">
                <div><dt>event</dt><dd className="mono">{e.kind.toUpperCase()}</dd></div>
                <div><dt>seq</dt><dd className="mono">#{e.seq}</dd></div>
                <div><dt>actor</dt><dd className="mono">{e.actor}</dd></div>
                <div><dt>at</dt><dd className="mono">{new Date(e.at_ms).toISOString()}</dd></div>
                <div><dt>detail</dt><dd className="mono wrap">{e.detail}</dd></div>
              </dl>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

function humanDetail(e: RequestEvent): string {
  const d = e.detail;
  if (e.kind === "command_allowed") {
    const m = /^(\S+) \(use (\d+)\/(\d+)\)/.exec(d);
    if (m) return `${actionCommand(m[1])} — use ${m[2]} of ${m[3]}`;
  }
  if (e.kind === "command_denied") {
    const m = /^([a-z_]+): attempted (.+?)(?: \((.*)\))?(?: session=.*)?$/.exec(d);
    if (m) {
      const what = m[2].startsWith("`") ? m[2].replace(/ sha256=.*$/, "").replace(/`/g, "") + " …" : actionCommand(m[2]);
      return `${what} — ${m[3] ?? CODE_WHY[m[1]] ?? m[1].replace(/_/g, " ")}`;
    }
  }
  if (e.kind === "credential_issued") {
    const m = /serial (\d+) valid until (\d+)/.exec(d);
    if (m) return `serial ${m[1]} · valid until ${clock(Number(m[2]) * 1000)}`;
  }
  if (e.kind === "request_created") {
    const m = /^(.+?) on (\S+) for (\d+)s$/.exec(d);
    if (m) return `${m[1]} on ${m[2]} for ${formatDuration(Number(m[3]))}`;
  }
  return d;
}

export function RequestLine({ r, label, right }: { r: AccessRequest; label: (id: string) => string; right?: ReactNode }) {
  return (
    <a className="req-line" href={`#/console/requests/${r.id}`}>
      <span className="req-id mono">#{r.id}</span>
      <span className="req-main">
        <span className="req-title">
          <strong>{label(r.agent_id)}</strong> <span className="muted">·</span> {actionTitle(r.action)} <span className="muted">on</span> <span className="mono">{r.resource_id}</span>
        </span>
        <span className="req-sub">{r.reason}</span>
      </span>
      <span className="req-right">{right ?? <StateBadge state={r.state} />}</span>
    </a>
  );
}

export function DenialRow({ d, label }: { d: Denial; label: (id: string) => string }) {
  return (
    <a className="denial" href={`#/console/requests/${d.request.id}`}>
      <span className="denial-icon"><Icon name="x" size={14} /></span>
      <span className="denial-main">
        <span>
          <strong>{label(d.request.agent_id)}</strong> attempted <code className="mono inline-cmd">{d.attempted}</code> on <span className="mono">{d.request.resource_id}</span>
        </span>
        <span className="denial-why">
          <Badge tone="danger" dot={false}>Denied</Badge> {d.why}
        </span>
      </span>
      <span className="denial-time muted">{timeAgo(d.event.at_ms)}</span>
    </a>
  );
}
