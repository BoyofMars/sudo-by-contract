// sbc-relay — private context + notification relay for Sudo by Contract.
//
//   SBC_CONTRACT=sbc.example.testnet node apps/relay/src/main.ts

import { DEFAULT_TESTNET_RPC, NearRpc, SudoContract } from "../../../packages/sbc-client/src/index.ts";
import { FanoutNotifier, SlackWebhookNotifier, type Notifier } from "./notify.ts";
import { createRelay } from "./server.ts";
import { RelayStore } from "./store.ts";
import { RequestWatcher } from "./watcher.ts";

const env = process.env;
const contractId = env.SBC_CONTRACT;
if (!contractId) {
  console.error("SBC_CONTRACT is required (the policy contract account id)");
  process.exit(2);
}
const rpcUrl = env.SBC_RPC ?? DEFAULT_TESTNET_RPC;
const port = Number(env.PORT ?? 8787);
const retentionDays = Number(env.SBC_RETENTION_DAYS ?? 30);
const contract = new SudoContract(contractId, new NearRpc(rpcUrl));
const store = new RelayStore(env.SBC_DB ?? "./relay.sqlite");
const log = (m: string) => console.log(`[relay] ${new Date().toISOString()} ${m}`);

const notifiers: Notifier[] = [];
if (env.SBC_WEBHOOK_URL) notifiers.push(new SlackWebhookNotifier(env.SBC_WEBHOOK_URL));

const watcher = new RequestWatcher({ recentRequests: () => contract.requests({ limit: 50 }) });

const relay = createRelay({
  store,
  contractId,
  rpcUrl,
  consoleUrl: env.SBC_CONSOLE_URL ?? null,
  corsOrigins: (env.SBC_CORS_ORIGINS ?? "*").split(",").map((s) => s.trim()).filter(Boolean),
  resolver: async (pk) => (await contract.whoami(pk)).binding,
  watcher,
  notifier: notifiers.length ? new FanoutNotifier(notifiers, (n, e) => log(`${n.name} failed: ${e instanceof Error ? e.message : e}`)) : undefined,
  health: async () => {
    const o = await contract.overview();
    return { chain_reachable: true, audit_seq: o.audit_seq };
  },
  log,
});

watcher.start(Number(env.SBC_POLL_MS ?? 2000));
const prune = () => {
  const r = store.prune(Date.now() - retentionDays * 86_400_000);
  if (r.contexts || r.reports) log(`retention: pruned ${r.contexts} contexts, ${r.reports} reports older than ${retentionDays}d`);
};
prune();
setInterval(prune, 3_600_000).unref();

relay.server.listen(port, () => {
  log(`listening on :${port} for ${contractId} via ${rpcUrl}`);
  log(`notifications: ${notifiers.length ? notifiers.map((n) => n.name).join(", ") : "none (set SBC_WEBHOOK_URL)"}; retention ${retentionDays}d`);
});

const shutdown = () => {
  watcher.stop();
  relay.close();
  store.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
