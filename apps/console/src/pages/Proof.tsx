// /#/proof — "Don't trust us. Verify it."
//
// Runs packages/sbc-client/src/proof.ts in the browser: every fact comes from
// NEAR RPC, the Ed25519 check runs locally with WebCrypto. Same checks as
// `npm run verify:live`.

import { useCallback, useEffect, useRef, useState } from "react";
import { verifyDeployment, type ProofReport, type ProofStep } from "@sbc/client";
import { Icon, Mark } from "../components/Icon.tsx";
import { Command, CopyButton, cx } from "../components/ui.tsx";
import { resolveConfig } from "../lib/config.ts";
import { useTheme } from "../lib/hooks.ts";

const LIVE_CONTRACT = (import.meta.env.VITE_SBC_LIVE_CONTRACT as string | undefined)?.trim() || "bagyard-sexton.testnet";
const EXPLORER = "https://testnet.nearblocks.io";

function iso(unix: number) {
  return new Date(unix * 1000).toISOString().replace(".000Z", "Z");
}

function StepMark({ status }: { status: ProofStep["status"] }) {
  if (status === "pass") return <span className="pf-mark pass"><Icon name="check" size={13} /></span>;
  if (status === "fail") return <span className="pf-mark fail"><Icon name="x" size={13} /></span>;
  return <span className={cx("pf-mark", status)} />;
}

export function Proof({ query }: { query: URLSearchParams }) {
  const [theme, setTheme] = useTheme();
  const contractId = (query.get("contract") || LIVE_CONTRACT).trim();
  const rpcUrl = resolveConfig().rpcUrl;
  const [steps, setSteps] = useState<ProofStep[]>([]);
  const [report, setReport] = useState<ProofReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const runId = useRef(0);

  const run = useCallback(async () => {
    const id = ++runId.current;
    setReport(null);
    setError(null);
    setElapsed(null);
    setSteps([]);
    const t0 = performance.now();
    try {
      const r = await verifyDeployment({ contractId, rpcUrl, onStep: (s) => id === runId.current && setSteps(s) });
      if (id !== runId.current) return;
      setReport(r);
      setSteps(r.steps);
      setElapsed(performance.now() - t0);
    } catch (e) {
      if (id === runId.current) setError(e instanceof Error ? e.message : String(e));
    }
  }, [contractId, rpcUrl]);

  useEffect(() => {
    void run();
  }, [run]);

  const total = steps.length || 7;
  const passed = steps.filter((s) => s.status === "pass").length;
  const failed = steps.some((s) => s.status === "fail");
  const done = !!report || !!error;
  const cert = report?.certificate;

  return (
    <div className="landing proof-page">
      <header className="l-nav">
        <a className="brand" href="#/"><Mark size={20} /><span>Sudo by Contract</span></a>
        <div className="l-nav-right">
          <a className="btn btn-ghost hide-sm" href="#/">Home</a>
          <button className="btn btn-ghost btn-icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle theme">
            <Icon name={theme === "dark" ? "sun" : "moon"} />
          </button>
          <a className="btn btn-primary" href="#/console">Open console</a>
        </div>
      </header>

      <main className="pf">
        <section className="pf-head">
          <p className="eyebrow">Independent verification</p>
          <h1>Don't trust us. Verify it.</h1>
          <p className="lead">
            Your browser asks NEAR directly — no keys, no accounts, no server of ours in the loop — and checks the claim everything rests on: <strong>the SSH certificate authority has no private key, and only the policy contract can sign with it.</strong>
          </p>
          <div className="pf-meta">
            <span className="pf-chip"><em>contract</em><span className="mono">{contractId}</span></span>
            <span className="pf-chip hide-sm"><em>rpc</em><span className="mono">{rpcUrl.replace(/^https?:\/\//, "")}</span></span>
            <button className="btn btn-secondary btn-xs" onClick={() => void run()} disabled={!done}>
              <Icon name="refresh" size={13} /> Verify again
            </button>
          </div>
        </section>

        <section className={cx("pf-status", done && !failed && !error && "ok", (failed || error) && "bad")} aria-live="polite">
          <div className="pf-status-text">
            {error ? (
              <><strong>Could not reach NEAR.</strong> <span>{error}</span></>
            ) : !done ? (
              <><strong className="pulse-text">Verifying against NEAR testnet…</strong> <span className="mono">{passed} of {total}</span></>
            ) : failed ? (
              <><strong>{passed} of {total} verified.</strong> <span>A check failed — details below.</span></>
            ) : (
              <>
                <strong>{passed} of {total} verified{elapsed ? <span className="pf-time mono"> in {(elapsed / 1000).toFixed(1)} s</span> : null}.</strong>
                <span>The CA's key is held by no one: {report?.threshold} of {report?.participants} independent MPC nodes must cooperate, and only <span className="mono">{contractId}</span> can ask them.</span>
              </>
            )}
          </div>
          <div className="pf-bar" aria-hidden>
            <span className="pf-bracket">[</span>
            {Array.from({ length: total }).map((_, i) => (
              <span key={i} className={cx("pf-seg", steps[i]?.status)} />
            ))}
            <span className="pf-bracket">]</span>
          </div>
        </section>

        <div className="pf-grid">
          <ol className="pf-steps">
            {(steps.length ? steps : Array.from({ length: 7 }, () => null)).map((s, i) => (
              <li key={i} className={cx("pf-step", s?.status ?? "pending")}>
                <span className="pf-n mono">{String(i + 1).padStart(2, "0")}</span>
                <StepMark status={s?.status ?? "pending"} />
                <div className="pf-body">
                  {s ? (
                    <>
                      <strong>{s.title}</strong>
                      <p className="pf-claim">{s.claim}</p>
                      {s.status === "running" ? <p className="pf-detail pulse-text">Asking NEAR…</p> : null}
                      {s.detail && s.status !== "running" ? <p className="pf-detail">{s.detail}</p> : null}
                      {s.facts?.length && s.status !== "running" ? (
                        <dl className="pf-facts">
                          {s.facts.map(([k, v]) => (
                            <div key={k}>
                              <dt>{k}</dt>
                              <dd className="mono">{v}</dd>
                            </div>
                          ))}
                        </dl>
                      ) : null}
                    </>
                  ) : (
                    <span className="pf-skel" />
                  )}
                </div>
              </li>
            ))}
          </ol>

          <aside className="pf-aside">
            <div className="pf-card">
              <div className="pf-card-head">
                <span className="eyebrow">The certificate</span>
                {cert ? <CopyButton text={cert.line} label="Copy" /> : null}
              </div>
              {cert ? (
                <>
                  <div className="code-title mono">ssh-keygen -L -f issued-cert.pub</div>
                  <pre className="code-block pf-cert">{`Type: ssh-ed25519-cert-v01@openssh.com user certificate
Signing CA: ED25519 (MPC-derived for ${contractId})
Key ID: "${cert.summary.keyId}"
Serial: ${cert.summary.serial}
Valid: from ${iso(cert.summary.validAfter)}
         to ${iso(cert.summary.validBefore)}
Principals:
        ${cert.summary.principals.join("\n        ")}
Critical Options:
        ${Object.entries(cert.summary.criticalOptions).map(([k, v]) => `${k} ${v}`).join("\n        ")}
Extensions: ${cert.summary.extensions.length ? cert.summary.extensions.join(", ") : "(none)"}`}</pre>
                  <p className="small muted">
                    Issued for capability <a href={`#/console/requests/${cert.request.id}?contract=${contractId}`}>#{cert.request.id}</a> ({cert.request.action} on {cert.request.resource_id}). Certificates are public by design: useless without the agent's ephemeral private key.
                  </p>
                </>
              ) : (
                <p className="small muted">{done ? "No issued certificate found." : "Fetching the most recent certificate the contract issued…"}</p>
              )}
            </div>

            <div className="pf-card">
              <span className="eyebrow">Run it in your terminal</span>
              <p className="small muted">Same checks, plus OpenSSH's own <code>ssh-keygen</code> as a second opinion. No keys or accounts needed.</p>
              <Command>{"npm run verify:live"}</Command>
            </div>

            <div className="pf-card pf-links">
              <span className="eyebrow">On the explorer</span>
              <a href={`${EXPLORER}/address/${contractId}`} target="_blank" rel="noreferrer">Policy contract <span className="mono">{contractId}</span> <Icon name="external" size={12} /></a>
              {report?.mpcContract ? (
                <a href={`${EXPLORER}/address/${report.mpcContract}`} target="_blank" rel="noreferrer">MPC signer <span className="mono">{report.mpcContract}</span> <Icon name="external" size={12} /></a>
              ) : null}
              <a href={`#/console?contract=${contractId}`}>Live console (read-only) <Icon name="arrow" size={12} /></a>
            </div>
          </aside>
        </div>
      </main>
    </div>
  );
}
