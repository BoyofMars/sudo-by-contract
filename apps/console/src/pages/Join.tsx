import { useEffect, useState } from "react";
import type { EnrollResult } from "@sbc/client";
import { Icon, Mark } from "../components/Icon.tsx";
import { Badge, cx } from "../components/ui.tsx";
import { useData } from "../lib/data/context.tsx";
import { friendlyError } from "../lib/data/source.ts";
import { supportsEd25519 } from "../lib/devicekey.ts";

type Step = "ready" | "keygen" | "submit" | "done" | "error";

export function Join({ query }: { query: URLSearchParams }) {
  const { source, reloadIdentity } = useData();
  const token = query.get("token") ?? "";
  const [step, setStep] = useState<Step>("ready");
  const [res, setRes] = useState<EnrollResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);
  useEffect(() => { supportsEd25519().then(setSupported); }, []);

  const go = async () => {
    setErr(null);
    setStep("keygen");
    await new Promise((r) => setTimeout(r, 350));
    setStep("submit");
    try {
      const r = await source.enrollDevice(token);
      setRes(r);
      if (r.ok) {
        setStep("done");
        reloadIdentity();
      } else {
        setErr(r.message);
        setStep("error");
      }
    } catch (e) {
      setErr(friendlyError(e));
      setStep("error");
    }
  };

  const steps: { k: Step; label: string }[] = [
    { k: "keygen", label: "Generate a non-extractable Ed25519 key in this browser" },
    { k: "submit", label: "Bind it on the contract with the one-time token" },
    { k: "done", label: "Token burned · device enrolled" },
  ];
  const order: Step[] = ["ready", "keygen", "submit", "done"];

  return (
    <div className="join">
      <div className="join-card">
        <a className="brand" href="#/"><Mark size={22} /> <span>Sudo by Contract</span></a>
        <h1>Enroll this device</h1>
        <p className="muted">
          You were invited to approve (or administer) infrastructure access on <span className="mono">{source.contractId}</span>.
          No wallet and no seed phrase: this browser creates its own key, which can sign approvals but can never be exported.
        </p>
        {source.mode === "preview" ? (
          <p className="note">
            <span>Preview mode — enrollment is simulated. Open the link with <span className="mono">contract=&lt;account&gt;</span> to enroll for real.</span>
          </p>
        ) : null}
        {!token ? <p className="note note-danger">This link has no token. Ask your admin for a fresh one.</p> : null}
        {supported === false ? <p className="note note-danger">This browser does not support WebCrypto Ed25519. Use a current Chrome, Edge, Firefox or Safari.</p> : null}

        <ol className="join-steps">
          {steps.map((s) => {
            const i = order.indexOf(s.k);
            const cur = order.indexOf(step === "error" ? "submit" : step);
            const state = step === "error" && s.k === "submit" ? "fail" : cur > i || step === "done" ? "done" : cur === i ? "doing" : "todo";
            return (
              <li key={s.k} className={cx(`is-${state}`)}>
                <span className="issue-dot">{state === "done" ? <Icon name="check" size={12} /> : state === "fail" ? <Icon name="x" size={12} /> : null}</span>
                {s.label}
              </li>
            );
          })}
        </ol>

        {step === "done" && res ? (
          <div className="join-done">
            <div>Enrolled as <Badge tone="active">{res.role}</Badge> <span className="mono">{res.principal}</span></div>
            <a className="btn btn-primary btn-lg btn-block" href="#/console">Open the console <Icon name="arrow" size={14} /></a>
          </div>
        ) : (
          <>
            {err ? <p className="note note-danger">{err}</p> : null}
            <button className="btn btn-primary btn-lg btn-block" disabled={!token || supported === false || step === "keygen" || step === "submit"} onClick={go}>
              {step === "keygen" ? "Generating key…" : step === "submit" ? "Enrolling on NEAR…" : step === "error" ? "Try again" : "Create device key & enroll"}
            </button>
          </>
        )}
        <p className="small muted">The key lives in this browser profile only. Lose the device, and an admin removes the key on-chain; enroll a new device with a new link.</p>
      </div>
    </div>
  );
}
