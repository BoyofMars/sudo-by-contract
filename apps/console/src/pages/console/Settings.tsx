import { useState } from "react";
import { DEFAULT_TESTNET_RPC } from "@sbc/client";
import { Icon } from "../../components/Icon.tsx";
import { Badge, Command, CopyButton, Dialog, ErrorNote, Field, KV, PageHeader, Panel, Truncate } from "../../components/ui.tsx";
import { useData, useQuery } from "../../lib/data/context.tsx";
import { useAction, useIsAdmin } from "../../lib/hooks.ts";
import { clearConfig, resolveConfig, saveConfig } from "../../lib/config.ts";
import type { EnrollmentToken } from "../../lib/data/source.ts";
import { dateTime } from "../../lib/events.ts";

export function Settings() {
  const { source, identity, reloadIdentity } = useData();
  const isAdmin = useIsAdmin();
  const action = useAction();
  const cfg = resolveConfig();
  const [conn, setConn] = useState({ contractId: cfg.contractId ?? "", rpcUrl: cfg.rpcUrl || DEFAULT_TESTNET_RPC, relayUrl: cfg.relayUrl ?? "" });
  const ov = useQuery((s) => s.overview(), []);
  const approvers = useQuery((s) => s.approvers(), []);
  const [envName, setEnvName] = useState("");
  const [invite, setInvite] = useState<{ id: string; label: string; admin: boolean } | null>(null);
  const [inviteToken, setInviteToken] = useState<EnrollmentToken | null>(null);
  const [notif, setNotif] = useState<NotificationPermission | "unsupported">(typeof Notification === "undefined" ? "unsupported" : Notification.permission);

  const apply = () => {
    if (!conn.contractId.trim()) {
      clearConfig();
    } else {
      saveConfig({ contractId: conn.contractId.trim(), rpcUrl: conn.rpcUrl.trim() || DEFAULT_TESTNET_RPC, relayUrl: conn.relayUrl.trim() || null });
    }
    // drop any ?contract= in the URL so the saved config wins, then reload
    window.location.href = window.location.pathname + "#/console";
    window.location.reload();
  };

  const joinLink = inviteToken ? `${window.location.origin}${window.location.pathname}#/join?contract=${encodeURIComponent(source.contractId)}&token=${encodeURIComponent(inviteToken.token)}${source.relayUrl && source.mode === "live" ? `&relay=${encodeURIComponent(source.relayUrl)}` : ""}` : "";

  return (
    <div className="page">
      <PageHeader title="Settings" subtitle="Which contract this console reads, this browser's device key, and each environment's certificate authority." />

      <Panel title="Connection">
        <form className="form" onSubmit={(e) => { e.preventDefault(); apply(); }}>
          <Field label="Policy contract" hint="The NEAR account the Sudo by Contract policy contract is deployed to. Leave empty for the simulated preview.">
            <input className="input mono" value={conn.contractId} onChange={(e) => setConn({ ...conn, contractId: e.target.value })} placeholder="sbc.example.testnet" />
          </Field>
          <div className="form-row">
            <Field label="NEAR RPC">
              <input className="input mono" value={conn.rpcUrl} onChange={(e) => setConn({ ...conn, rpcUrl: e.target.value })} />
            </Field>
            <Field label="Private relay (optional)" hint="Off-chain context documents, redacted gate reports, live events.">
              <input className="input mono" value={conn.relayUrl} onChange={(e) => setConn({ ...conn, relayUrl: e.target.value })} placeholder="https://relay.example.com" />
            </Field>
          </div>
          <div className="form-actions">
            {source.mode === "live" ? <button type="button" className="btn btn-secondary" onClick={() => { window.location.href = window.location.pathname + "#/console?preview=1"; }}>Try simulation</button> : null}
            <button className="btn btn-primary">Save & reconnect</button>
          </div>
        </form>
      </Panel>

      <Panel title="This device">
        {source.mode === "preview" ? (
          <p className="quiet-note">Preview uses a simulated admin identity. In live mode this panel shows the browser's own device key.</p>
        ) : identity?.publicKey ? (
          <>
            <KV
              cols={1}
              items={[
                ["Device key", <span className="row-gap"><Truncate text={identity.publicKey} head={20} tail={8} /><CopyButton text={identity.publicKey} compact /></span>],
                ["Role", identity.binding ? <Badge tone="active">{identity.binding.role}</Badge> : <Badge tone="danger">not bound on the contract</Badge>],
                ["Principal", identity.binding?.principal ?? "—"],
              ]}
            />
            <p className="small muted">
              Generated in this browser as a non-extractable WebCrypto Ed25519 key. The page can ask it to sign; nothing — including this console — can export it. On-chain it is a function-call key on <span className="mono">{source.contractId}</span> restricted to the methods of its role.
            </p>
            <div className="form-actions">
              <button className="btn btn-ghost" onClick={reloadIdentity}><Icon name="refresh" size={14} /> Re-check</button>
              <button className="btn btn-danger" onClick={() => action.run(async () => { await source.forgetDevice(); reloadIdentity(); }, "Device key forgotten. Ask an admin to remove it on-chain too.")}>Forget this device</button>
            </div>
          </>
        ) : (
          <p className="quiet-note">This browser has no device key for <span className="mono">{source.contractId}</span>, so it can read everything but change nothing. To approve from here, open a one-time join link from an admin.</p>
        )}
      </Panel>

      {source.mode === "live" && source.relayUrl && identity?.binding ? (
        <Panel title="Notifications">
          <p className="small muted">
            With the console open, approval requests arrive instantly over the relay's event stream and raise a browser notification.
          </p>
          <div className="form-actions">
            {notif === "unsupported" ? <span className="muted">Not supported in this browser.</span> : notif === "granted" ? <Badge tone="active">Enabled</Badge> : (
              <button className="btn btn-secondary" onClick={async () => setNotif(await Notification.requestPermission())}><Icon name="bell" size={14} /> Enable browser notifications</button>
            )}
          </div>
        </Panel>
      ) : null}

      <Panel title="Environments & certificate authorities">
        <p className="small muted">Each environment's CA is an Ed25519 key the NEAR MPC network derives for this contract at <span className="mono">sbc/ssh-user-ca/v{ov.data?.config.ca_version ?? 1}/&lt;env&gt;</span>. Paste the line into a host's <span className="mono">TrustedUserCAKeys</span> (the gate's enroll command does this for you).</p>
        <div className="stack">
          {(ov.data?.environments ?? []).map((e) => (
            <div key={e.name} className="env-row">
              <div className="env-head">
                <strong>{e.name}</strong>
                {e.ca_public_key ? <Badge tone="active">CA ready</Badge> : <Badge tone="pending">waiting for MPC</Badge>}
                {e.ca_public_key_ssh ? <CopyButton text={e.ca_public_key_ssh} label="Copy CA line" /> : null}
              </div>
              {e.ca_public_key_ssh ? <pre className="code-block wrap">{e.ca_public_key_ssh}</pre> : null}
            </div>
          ))}
        </div>
        {isAdmin ? (
          <form className="inline-form" onSubmit={async (e) => { e.preventDefault(); if (await action.run(() => source.addEnvironment(envName.trim()), `Environment ${envName} created — deriving CA key`).then((r) => r.ok)) setEnvName(""); }}>
            <input className="input mono" placeholder="staging" value={envName} onChange={(e) => setEnvName(e.target.value.toLowerCase())} />
            <button className="btn btn-secondary" disabled={!/^[a-z0-9](?:[a-z0-9]|-(?!-)){0,61}[a-z0-9]$/.test(envName) || action.busy}>Add environment</button>
          </form>
        ) : null}
      </Panel>

      <Panel title="Approvers" actions={isAdmin ? <button className="btn btn-secondary btn-xs" onClick={() => { setInviteToken(null); setInvite({ id: "", label: "", admin: false }); }}><Icon name="plus" size={12} /> Invite</button> : null}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Approver</th><th>Role</th><th>Devices</th><th>Status</th></tr></thead>
            <tbody>
              {(approvers.data ?? []).map((a) => (
                <tr key={a.id}>
                  <td>{a.label} <div className="cell-sub mono">{a.id}</div></td>
                  <td>{a.is_admin ? "Admin" : "Approver"}</td>
                  <td className="mono">{a.keys.length}</td>
                  <td><Badge tone={a.status === "Active" ? "active" : "muted"}>{a.status}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Bootstrapping a new contract">
        <p className="small muted">The owner account (a normal NEAR account, kept offline) creates the first admin and its enrollment token; everything after that happens here with device keys.</p>
        <Command>{`near contract call-function as-transaction <contract> create_approver json-args '{"id":"you","label":"You","is_admin":true}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' sign-as <owner> network-config testnet sign-with-keychain send`}</Command>
        <p className="small muted">Then register a one-time enrollment token for that admin (<span className="mono">create_enrollment</span> with role <span className="mono">Admin</span> — the sudoctl CLI wraps this) and open the resulting <span className="mono">#/join?contract=…&amp;token=…</span> link on the admin's device.</p>
      </Panel>

      <Dialog open={!!invite} onClose={() => setInvite(null)} title={inviteToken ? "Share this link" : "Invite approver"} wide>
        {invite && !inviteToken ? (
          <form
            className="form"
            onSubmit={async (e) => {
              e.preventDefault();
              const a = await action.run(() => source.createApprover(invite.id, invite.label.trim(), invite.admin));
              if (!a.ok) return;
              const t = await action.run(() => source.createEnrollment(invite.admin ? "Admin" : "Approver", invite.id, 24 * 3600));
              if (t.ok) setInviteToken(t.value);
            }}
          >
            <div className="form-row">
              <Field label="Approver id"><input className="input mono" value={invite.id} onChange={(e) => setInvite({ ...invite, id: e.target.value.toLowerCase() })} placeholder="maya" /></Field>
              <Field label="Name"><input className="input" value={invite.label} onChange={(e) => setInvite({ ...invite, label: e.target.value })} placeholder="Maya Okafor" /></Field>
            </div>
            <label className="check-inline"><input type="checkbox" checked={invite.admin} onChange={(e) => setInvite({ ...invite, admin: e.target.checked })} /> Admin (can change policy, resources, agents)</label>
            <ErrorNote error={action.error} />
            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => setInvite(null)}>Cancel</button>
              <button className="btn btn-primary" disabled={!invite.id || !invite.label.trim() || action.busy}>{action.busy ? "Creating on NEAR…" : "Create invite"}</button>
            </div>
          </form>
        ) : inviteToken ? (
          <div className="enroll">
            <p>Send this one-time link to <strong>{invite?.label}</strong> over a channel you trust. Opening it creates a non-extractable device key in their browser and binds it. It expires {dateTime(inviteToken.expiresAtMs)}.</p>
            <div className="cmd"><pre className="wrap">{joinLink}</pre><CopyButton text={joinLink} compact /></div>
          </div>
        ) : null}
      </Dialog>
    </div>
  );
}
