import { useState } from "react";
import { EscapePlayground } from "../components/EscapePlayground.tsx";
import { HeroTerminal } from "../components/HeroTerminal.tsx";
import { Icon, Mark } from "../components/Icon.tsx";
import { cx } from "../components/ui.tsx";
import { useTheme } from "../lib/hooks.ts";

const go = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });

const FLOW = [
  { k: "Request", d: "The agent names one action, one host, a duration and its reason — signed with its own key." },
  { k: "Evaluate", d: "The contract checks every policy. Deny wins. Nothing is allowed by default." },
  { k: "Approve", d: "Zero, one or several humans approve from any device. They can narrow the window, never widen it." },
  { k: "Issue", d: "The contract builds the certificate; the NEAR MPC network signs it; the contract verifies before issuing." },
  { k: "Execute", d: "The host gate turns the command into a typed action and asks the contract to consume one use." },
  { k: "Observe", d: "Every allowed and denied command is an event. Redacted text stays private." },
  { k: "Expire", d: "The window closes on its own. Single use closes it sooner. Revocation closes it now." },
];

const CONTRAST = [
  ["Lifetime", "Until someone remembers to rotate it", "Ten minutes, checked by sshd and the contract"],
  ["Scope", "Whatever the account can do", "One typed action on one host"],
  ["After the task", "Still valid", "Consumed — single use closes it"],
  ["If exfiltrated", "Full blast radius", "One restart of one service, until expiry"],
  ["Who decided", "Whoever provisioned the key", "A versioned policy and named approvers, on-chain"],
  ["Evidence", "Logs you hope were kept", "Hash-chained events; denials are records too"],
];

const CMP: { row: string; cells: string[] }[] = [
  { row: "Short-lived SSH certificates", cells: ["Yes", "Yes (SSH secrets engine)", "Yes (via Vault or injected credentials)", "Yes"] },
  { row: "Who holds the CA private key", cells: ["The Auth Service (HSM / KMS supported)", "The Vault cluster", "Vault, or the target's own credentials", "Nobody: threshold-signed by NEAR MPC for the contract"] },
  { row: "Policy verifiable by outsiders", cells: ["Roles inside the cluster", "HCL policies inside Vault", "Scopes inside the controller", "On-chain, versioned and hashed; anyone can audit"] },
  { row: "Unit of authority", cells: ["Login as a role (+ recording, moderation)", "Principals and certificate options", "A session to a target", "One typed action, N uses, checked per command"] },
  { row: "Built for", cells: ["Human engineers, broad protocol coverage", "Secrets and machine credentials", "Human sessions without VPNs", "Software that asks for authority (agents)"] },
  { row: "Maturity", cells: ["Battle-tested", "Battle-tested", "Production-ready", "Early: SSH first; Kubernetes and cloud adapters next"] },
];

/** Set at build time for hosted deployments (e.g. VITE_SBC_LIVE_CONTRACT=bagyard-sexton.testnet). */
const LIVE_CONTRACT = (import.meta.env.VITE_SBC_LIVE_CONTRACT as string | undefined)?.trim() || null;

const SNIPPETS: Record<string, string> = {
  CLI: `$ sudoctl request restart checkout-api --on prod-web-02 --for 10m \\
    --reason "checkout-api unresponsive after deploy #1842"
request #1042 · awaiting approval (production-service-remediation)

$ sudoctl wait 1042
✓ approved by tobi · certificate serial 1042 · valid 10m · 1 use

$ sudoctl exec 1042 -- sudo systemctl restart checkout-api
✓ allowed · service.restart:checkout-api · use 1/1`,
  SDK: `// an agent asks for exactly what it needs, then gives it back
const cap = await sudo.request({
  resource: "prod-web-02",
  action: "service.restart:checkout-api",
  duration: "10m",
  reason: "checkout-api unresponsive after deploy #1842",
  evidence: [{ label: "error rate", value: "1.2% → 18%" }],
});

await cap.wait();                          // policy, humans, MPC signature
await cap.exec("sudo systemctl restart checkout-api", { host: "prod-web-02.internal" });
await cap.release();                       // authority ends now`,
  MCP: `{
  "mcpServers": {
    "sudo-by-contract": {
      "command": "node",
      "args": ["apps/sbc-mcp/src/main.ts"],
      "env": { "SBC_CONTRACT": "sbc.example.testnet", "SBC_AGENT_KEY_FILE": "~/.sbc/keys/agent-deploy-agent.json" }
    }
  }
}
// The agent gets tools to request a capability, run the approved
// action, and release it. It never sees a long-lived credential.`,
};

export function Landing() {
  const [theme, setTheme] = useTheme();
  const [tab, setTab] = useState<keyof typeof SNIPPETS>("CLI");
  return (
    <div className="landing">
      <header className="l-nav">
        <a className="brand" href="#/"><Mark size={20} /><span>Sudo by Contract</span></a>
        <nav className="l-links">
          <button onClick={() => go("flow")}>How it works</button>
          <button onClick={() => go("enforcement")}>Enforcement</button>
          <button onClick={() => go("escape")}>Try to escape</button>
          <button onClick={() => go("no-key")}>No master key</button>
          <a className="l-link" href="#/proof">Verify live</a>
          <button onClick={() => go("compare")}>Compare</button>
          <button onClick={() => go("developers")}>Developers</button>
        </nav>
        <div className="l-nav-right">
          <button className="btn btn-ghost btn-icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle theme">
            <Icon name={theme === "dark" ? "sun" : "moon"} />
          </button>
          <a className="btn btn-primary" href="#/console">Open console</a>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Ephemeral machine authority for AI agents</p>
          <h1>Give agents permission, not credentials.</h1>
          <p className="lead">
            An agent asks to restart one service on one server for ten minutes. Policy approves exactly that. A short-lived certificate is issued for that single action, and the authority is gone when the task is done.
          </p>
          <p className="lead strong-lead">No standing privilege. No master key anywhere.</p>
          <div className="hero-cta">
            <button className="btn btn-primary btn-lg" onClick={() => go("escape")}>Try to escape <Icon name="arrow" size={14} /></button>
            <a className="btn btn-secondary btn-lg" href="#/proof"><Icon name="shield" size={14} /> Verify it live</a>
          </div>
          {LIVE_CONTRACT ? (
            <p className="hero-live small">
              <span className="live-dot" aria-hidden /> Live on NEAR testnet · <a href={`#/console?contract=${LIVE_CONTRACT}`} className="mono">{LIVE_CONTRACT}</a> · <a href="#/console">console demo</a>
            </p>
          ) : null}
          <ul className="hero-proof">
            <li>OpenSSH certificates</li>
            <li>Typed action adapters</li>
            <li>NEAR threshold signing</li>
            <li>Hash-chained audit</li>
            <li>22/22 live on testnet</li>
          </ul>
        </div>
        <HeroTerminal />
      </section>

      <section className="l-section" id="problem">
        <div className="l-head">
          <p className="eyebrow">The problem</p>
          <h2>Root access should die before the task does.</h2>
          <p className="l-sub">Agents now restart services, run migrations and touch production. The usual way to let them is to hand over a credential — one that outlives the task, can be copied, and can do far more than the task needs.</p>
        </div>
        <div className="contrast">
          <div className="contrast-row contrast-head">
            <span />
            <span>“Here is a credential. Try to behave.”</span>
            <span>“Here is a capability. It is exactly what was approved.”</span>
          </div>
          {CONTRAST.map(([k, a, b]) => (
            <div key={k} className="contrast-row">
              <span className="ck">{k}</span>
              <span className="ca"><Icon name="x" size={13} /> {a}</span>
              <span className="cb"><Icon name="check" size={13} /> {b}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="l-section" id="flow">
        <div className="l-head">
          <p className="eyebrow">How it works</p>
          <h2>Authority exists only inside a window.</h2>
          <p className="l-sub">Every capability walks the same path, and every step leaves a record.</p>
        </div>
        <ol className="flow">
          {FLOW.map((f, i) => (
            <li key={f.k}>
              <span className="flow-n mono">{String(i + 1).padStart(2, "0")}</span>
              <strong>{f.k}</strong>
              <p>{f.d}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="l-section" id="enforcement">
        <div className="l-head">
          <p className="eyebrow">Enforcement</p>
          <h2>Enforced on the host, not in the UI.</h2>
          <p className="l-sub">Ignore the console entirely and the answer is the same. Four independent layers have to agree before a command runs.</p>
        </div>
        <div className="layers">
          <ol className="layer-list">
            <li>
              <span className="layer-n mono">1</span>
              <div>
                <strong>sshd verifies the certificate</strong>
                <p>The host trusts only its environment's CA. The principal <code>sbc-prod-web-02</code> makes a certificate for one host useless on any other; the validity window is checked on every connection. No PTY, no forwarding. Revoked serials land in a KRL.</p>
              </div>
            </li>
            <li>
              <span className="layer-n mono">2</span>
              <div>
                <strong>Every session is forced through the gate</strong>
                <p><code>force-command</code> is inside the signed certificate and in <code>sshd_config</code>. Whatever the agent typed, <code>sbc-gate</code> runs. There is no shell to escape to.</p>
              </div>
            </li>
            <li>
              <span className="layer-n mono">3</span>
              <div>
                <strong>Commands become typed actions — or nothing</strong>
                <p>A closed grammar (no quotes, no <code>;</code>, no <code>$</code>) maps the text to <code>service.restart:checkout-api</code> or refuses it. The gate then runs a fixed program with fixed arguments. Never a shell.</p>
              </div>
            </li>
            <li>
              <span className="layer-n mono">4</span>
              <div>
                <strong>The contract is asked before every exec</strong>
                <p><code>consume()</code> enforces scope, single use, expiry, revocation and host binding, and records the outcome. If the chain is unreachable, the answer is no.</p>
              </div>
            </li>
          </ol>
          <div className="layer-proof">
            <div className="code-title mono">ssh-keygen -L -f id_ed25519-cert.pub</div>
            <pre className="code-block">{`Type: ssh-ed25519-cert-v01@openssh.com user certificate
Signing CA: ED25519 SHA256:E9Jz…QmU  (MPC-derived for the contract)
Key ID: "sbc cap=1042 agent=deploy-agent res=prod-web-02"
Serial: 1042
Valid: from 14:02:11 to 14:12:11
Principals:
        sbc-prod-web-02
Critical Options:
        force-command /usr/local/sbin/sbc-gate
Extensions: (none)`}</pre>
            <p className="small muted">Root is not the default. The agent's account has no shell and no sudo of its own; <code>sudoers</code> allows exact command lines for enrolled services only.</p>
          </div>
        </div>
      </section>

      <section className="l-section" id="escape">
        <div className="l-head">
          <p className="eyebrow">Try to escape</p>
          <h2>You are the agent. Get out.</h2>
          <p className="l-sub">
            You hold one capability: restart <code>checkout-api</code> on <code>prod-web-02</code>, once, for ten minutes. Type what a compromised or prompt-injected agent would type. The verdict comes from the gate's own Rust code, compiled to WebAssembly and running in this tab.
          </p>
        </div>
        <EscapePlayground />
      </section>

      <section className="l-section" id="no-key">
        <div className="l-head">
          <p className="eyebrow">Signing</p>
          <h2>No CA key exists anywhere.</h2>
          <p className="l-sub">
            Short-lived certificates usually just move the problem: someone still holds the CA key. Here the CA is a key the NEAR MPC network derives for the policy contract's account. Its shares sit with independent nodes running in TEEs, and a threshold of them must cooperate to sign.
          </p>
        </div>
        <div className="sigflow">
          <div className="sig-node"><span className="mono small muted">01</span><strong>Policy contract</strong><span>builds the certificate body from the approved request</span></div>
          <Icon name="arrow" className="sig-arrow" />
          <div className="sig-node accent"><span className="mono small muted">02</span><strong>NEAR MPC network</strong><span>threshold Ed25519 signature under the contract's derived key</span></div>
          <Icon name="arrow" className="sig-arrow" />
          <div className="sig-node"><span className="mono small muted">03</span><strong>Contract verifies</strong><span>checks the signature, then issues — or fails closed</span></div>
          <Icon name="arrow" className="sig-arrow" />
          <div className="sig-node"><span className="mono small muted">04</span><strong>Host</strong><span>trusts the derived public key as its only user CA</span></div>
        </div>
        <a className="proof-cta" href="#/proof">
          <span className="proof-cta-mark"><Icon name="shield" size={18} /></span>
          <span className="proof-cta-text">
            <strong>Don't take our word for it.</strong>
            <span>Your browser can ask NEAR's MPC network for this CA key, fetch a certificate the contract really issued, and verify its signature. Seven checks, about five seconds, no account.</span>
          </span>
          <span className="proof-cta-go">Verify it live <Icon name="arrow" size={14} /></span>
        </a>
        <div className="caveat">
          <Icon name="alert" size={14} />
          <p>
            <strong>What this does not remove:</strong> whoever can upgrade the contract controls what it signs. Lock the contract account or put upgrades behind multi-party governance. Certificates themselves are public — they are useless without the agent's ephemeral private key.
          </p>
        </div>
      </section>

      <section className="l-section" id="compare">
        <div className="l-head">
          <p className="eyebrow">Compared honestly</p>
          <h2>Narrower and stricter, on purpose.</h2>
          <p className="l-sub">If you run Teleport, Vault or Boundary, keep them: they are excellent at human access, session recording and broad protocol coverage. Sudo by Contract is built for software that asks for authority, where the policy and the signer should not belong to a single operator.</p>
        </div>
        <div className="cmp-wrap">
          <table className="cmp">
            <thead>
              <tr><th /><th>Teleport</th><th>HashiCorp Vault</th><th>Boundary</th><th className="us">Sudo by Contract</th></tr>
            </thead>
            <tbody>
              {CMP.map((r) => (
                <tr key={r.row}>
                  <th>{r.row}</th>
                  {r.cells.map((c, i) => <td key={i} className={cx(i === 3 && "us")}>{c}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="l-section" id="developers">
        <div className="l-head">
          <p className="eyebrow">Developers</p>
          <h2>Request a capability like you'd call an API.</h2>
          <p className="l-sub">A CLI for people, an SDK for agents, an MCP server for assistants. All three sign with the agent's own enrolled key.</p>
        </div>
        <div className="dev">
          <div className="dev-tabs" role="tablist">
            {(Object.keys(SNIPPETS) as (keyof typeof SNIPPETS)[]).map((k) => (
              <button key={k} role="tab" aria-selected={tab === k} className={cx(tab === k && "on")} onClick={() => setTab(k)}>{k}</button>
            ))}
          </div>
          <pre className="code-block dev-code">{SNIPPETS[tab]}</pre>
        </div>
      </section>

      <section className="l-final">
        <h2>Ten minutes. One command. No permanent key.</h2>
        <div className="hero-cta">
          <a className="btn btn-primary btn-lg" href="#/console">Open the console</a>
          <span className="muted mono small">or run the sandbox: <span className="kbd">docker compose -f sandbox/docker-compose.yml up --build</span></span>
        </div>
      </section>

      <footer className="l-foot">
        <span><Mark size={16} /> Sudo by Contract</span>
        <span className="muted">A prototype built on NEAR. Read the threat model for what it does — and does not — defend against.</span>
      </footer>
    </div>
  );
}
