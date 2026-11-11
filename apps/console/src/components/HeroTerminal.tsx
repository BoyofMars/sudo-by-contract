// The landing page's scripted demonstration. A visualization of the real
// flow (not a live connection): request → policy → approval → threshold
// signature → bounded authority → allowed / denied / expired.

import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon.tsx";
import { cx } from "./ui.tsx";

type Kind = "cmd" | "out" | "ok" | "no" | "wait" | "banner" | "gap" | "dim";
interface Line {
  kind: Kind;
  text: string;
  sub?: string;
  delay: number; // ms after previous line
  phase?: Phase;
}
type Phase = "requested" | "evaluating" | "approval" | "signing" | "active" | "used" | "expired";

const SCRIPT: Line[] = [
  { kind: "cmd", text: "sudoctl request restart checkout-api --on prod-web-02 --for 10m", delay: 300, phase: "requested" },
  { kind: "dim", text: "reason: checkout error rate 1.2% → 18% after deploy #1842", delay: 650 },
  { kind: "out", text: "request #1042 submitted · policy production-service-remediation v3", delay: 700, phase: "evaluating" },
  { kind: "ok", text: "identity", sub: "deploy-agent", delay: 380 },
  { kind: "ok", text: "resource", sub: "prod-web-02 · production", delay: 300 },
  { kind: "ok", text: "action", sub: "restart checkout-api", delay: 300 },
  { kind: "ok", text: "duration", sub: "requested 10m / allowed 15m", delay: 300 },
  { kind: "wait", text: "approval", sub: "waiting for 1 human…", delay: 380, phase: "approval" },
  { kind: "ok", text: "approval", sub: "approved by tobi · from a phone", delay: 1700 },
  { kind: "wait", text: "signing", sub: "NEAR MPC threshold signature (Ed25519)…", delay: 450, phase: "signing" },
  { kind: "ok", text: "certificate", sub: "serial 1043 · principal sbc-prod-web-02 · no pty", delay: 1500 },
  { kind: "banner", text: "AUTHORIZATION ACTIVE", sub: "10:00 · 1 use · this host only", delay: 450, phase: "active" },
  { kind: "gap", text: "", delay: 250 },
  { kind: "cmd", text: "ssh prod-web-02 sudo systemctl restart checkout-api", delay: 900 },
  { kind: "ok", text: "allowed", sub: "service.restart:checkout-api · use 1/1", delay: 800, phase: "used" },
  { kind: "cmd", text: "ssh prod-web-02 sudo cat /etc/shadow", delay: 1100 },
  { kind: "no", text: "denied", sub: "`cat` is not an action that can be authorized", delay: 650 },
  { kind: "cmd", text: "ssh prod-web-02 sudo systemctl restart sshd", delay: 1100 },
  { kind: "no", text: "denied", sub: "capability permits only service.restart:checkout-api", delay: 650 },
  { kind: "dim", text: "… 10 minutes later", delay: 1300, phase: "expired" },
  { kind: "cmd", text: "ssh prod-web-02 sudo systemctl restart checkout-api", delay: 900 },
  { kind: "no", text: "denied", sub: "certificate expired — rejected by sshd", delay: 650 },
  { kind: "banner", text: "AUTHORITY GONE", sub: "nothing left to steal", delay: 600 },
];

const PHASES: { k: Phase; label: string }[] = [
  { k: "requested", label: "Request" },
  { k: "evaluating", label: "Evaluate" },
  { k: "approval", label: "Approve" },
  { k: "signing", label: "Issue" },
  { k: "active", label: "Execute" },
  { k: "used", label: "Observe" },
  { k: "expired", label: "Expire" },
];

export function HeroTerminal() {
  const reduced = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const [n, setN] = useState(reduced ? SCRIPT.length : 0);
  const [run, setRun] = useState(0);
  const [visible, setVisible] = useState(true);
  const ref = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(([e]) => setVisible(e.isIntersecting), { threshold: 0.2 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (reduced || !visible || n >= SCRIPT.length) return;
    const t = setTimeout(() => setN((x) => x + 1), SCRIPT[n].delay);
    return () => clearTimeout(t);
  }, [n, visible, reduced, run]);

  useEffect(() => {
    const b = bodyRef.current;
    if (b) b.scrollTop = b.scrollHeight;
  }, [n]);

  const shown = SCRIPT.slice(0, n);
  // collapse "wait" lines once their resolution arrives
  const lines = shown.filter((l, i) => !(l.kind === "wait" && shown.slice(i + 1).some((m) => m.kind === "ok" && (m.text === l.text || (l.text === "signing" && m.text === "certificate")))));
  const phase = [...shown].reverse().find((l) => l.phase)?.phase ?? "requested";
  const pIdx = PHASES.findIndex((p) => p.k === phase);
  const done = n >= SCRIPT.length;
  const windowState = pIdx >= 6 ? "expired" : pIdx >= 4 ? (pIdx >= 5 ? "used" : "active") : "none";

  return (
    <div className="hero-term" ref={ref} aria-label="Demonstration of an agent requesting, using and losing a capability">
      <div className="term-bar">
        <span className="term-dots"><i /><i /><i /></span>
        <span className="term-title mono">deploy-agent@ops</span>
        <button className="term-replay" onClick={() => { setN(0); setRun((r) => r + 1); }} aria-label="Replay demonstration" title="Replay">
          <Icon name="refresh" size={13} />
        </button>
      </div>
      <div className="term-body" ref={bodyRef}>
        {lines.map((l, i) => (
          <TermLine key={`${run}-${i}`} l={l} last={i === lines.length - 1 && !done} />
        ))}
        {!done && !reduced ? <span className="term-caret" /> : null}
      </div>
      <div className="term-foot">
        <div className="term-phases">
          {PHASES.map((p, i) => (
            <span key={p.k} className={cx("tp", i < pIdx && "past", i === pIdx && "now")}>{p.label}</span>
          ))}
        </div>
        <div className={cx("term-window", `tw-${windowState}`)}>
          <span className="tw-label mono">capability #1042</span>
          <span className="tw-track"><span className="tw-span"><i /></span></span>
          <span className="tw-state mono">{windowState === "none" ? "no authority" : windowState === "active" ? "active · 1 use" : windowState === "used" ? "used · 0 left" : "expired"}</span>
        </div>
      </div>
    </div>
  );
}

function TermLine({ l, last }: { l: Line; last: boolean }) {
  switch (l.kind) {
    case "cmd":
      return <div className="tl cmd"><span className="ps">$</span> {l.text}</div>;
    case "dim":
      return <div className="tl dim">{l.text}</div>;
    case "out":
      return <div className="tl out">→ {l.text}</div>;
    case "gap":
      return <div className="tl gap" />;
    case "banner":
      return (
        <div className={cx("tl banner", l.text.startsWith("AUTHORITY GONE") && "gone")}>
          <strong>{l.text}</strong> <span>{l.sub}</span>
        </div>
      );
    default:
      return (
        <div className={cx("tl chk", l.kind, last && l.kind === "wait" && "pulse-text")}>
          <span className="mk">{l.kind === "ok" ? "✓" : l.kind === "no" ? "✕" : "○"}</span>
          <span className="k">{l.text}</span>
          <span className="v">{l.sub}</span>
        </div>
      );
  }
}
