// Markdown summary of the capabilities a live-hero run created, read back from
// the contract (not from the agent's own output). Used as the GitHub Actions
// job summary.
//
//   node scripts/hero-summary.ts --since <unix-ms> [--contract id] [--resource id]

import { SudoContract, parseCertificateLine, type AccessRequest } from "../packages/sbc-client/src/index.ts";

const argv = process.argv.slice(2);
const flag = (n: string) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const contractId = flag("contract") ?? process.env.SBC_CONTRACT ?? "bagyard-sexton.testnet";
const resource = flag("resource") ?? process.env.SBC_RESOURCE ?? "prod-web-02";
const since = Number(flag("since") ?? 0);
const rpc = process.env.SBC_RPC ?? "https://rpc.testnet.fastnear.com";
const network = contractId.endsWith(".near") ? "" : "testnet.";
const console_ = (process.env.SBC_CONSOLE_URL ?? "https://sudo-by-contract.vercel.app").replace(/\/+$/, "");

const c = new SudoContract(contractId, rpc);
const all = await c.requests({ resource_id: resource, limit: 50 });
const runs = all.filter((r) => r.created_at_ms >= since).sort((a, b) => a.id - b.id);

const iso = (s: number) => new Date(s * 1000).toISOString().slice(11, 19);
const ev = (r: AccessRequest, kind: string) => r.events.findLast((e) => e.kind === kind);

const out: string[] = [];
out.push(`## Live run on NEAR testnet`);
out.push("");
out.push(`Policy contract [\`${contractId}\`](https://${network}nearblocks.io/address/${contractId}) · host \`${resource}\` (real OpenSSH + sbc-gate on this runner) · certificates signed by the NEAR MPC network.`);
out.push("");
if (!runs.length) {
  out.push("_No capability was requested in this run._");
} else {
  out.push("| # | Action | Approved by | Certificate | Uses | Denied attempts | Final state |");
  out.push("|---|---|---|---|---|---|---|");
  for (const r of runs) {
    let cert = "—";
    if (r.certificate) {
      const s = parseCertificateLine(r.certificate);
      cert = `serial ${s.serial}, ${iso(s.validAfter)}–${iso(s.validBefore)} UTC`;
    }
    const by = r.approvals.length ? r.approvals.map((a) => a.approver_id).join(", ") : r.required_approvals === 0 ? `policy \`${r.policy_id}\` (no human needed)` : "—";
    out.push(`| [#${r.id}](${console_}/#/console/requests/${r.id}?contract=${contractId}) | \`${r.action}\` | ${by} | ${cert} | ${r.uses}/${r.max_uses} | ${r.denied_attempts} | **${r.state}**${r.state_reason ? ` — ${r.state_reason}` : ""} |`);
  }
  const signed = runs.map((r) => ({ r, from: ev(r, "approval_granted") ?? ev(r, "request_created"), sig: ev(r, "credential_issued") })).filter((x) => x.from && x.sig);
  if (signed.length) {
    out.push("");
    out.push(signed.map(({ r, from, sig }) => `#${r.id}: certificate signed by the MPC network ${((sig!.at_ms - from!.at_ms) / 1000).toFixed(1)} s after ${from!.kind === "approval_granted" ? "approval" : "the request"}`).join(" · "));
  }
}
out.push("");
out.push(`Every row above is read back from the contract after the run; open a capability to see its on-chain event trail.`);
console.log(out.join("\n"));
