// The relay HTTP server. It is NOT in the authorization path: the contract
// and the host gate decide everything. The relay keeps private context
// off-chain, collects redacted gate reports, and pushes events to humans.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hexEncode, sha256, utf8, type Role } from "../../../packages/sbc-client/src/index.ts";
import type { GateReport } from "../../../packages/sbc-agent/src/relay-client.ts";
import { AuthError, RelayAuthenticator, type Authenticated, type BindingResolver } from "./auth.ts";
import type { Notifier } from "./notify.ts";
import type { RelayStore } from "./store.ts";
import type { RequestChange, RequestWatcher } from "./watcher.ts";

export interface RelayOptions {
  store: RelayStore;
  resolver: BindingResolver;
  watcher?: RequestWatcher;
  notifier?: Notifier;
  health?: () => Promise<{ chain_reachable: boolean; audit_seq: number | null }>;
  contractId: string;
  rpcUrl: string;
  consoleUrl?: string | null;
  corsOrigins?: string[];
  now?: () => number;
  log?: (msg: string) => void;
}

const MAX_CONTEXT_BYTES = 16 * 1024;
const MAX_REPORT_BYTES = 8 * 1024;
const READERS: Role[] = ["Admin", "Approver"];

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function readBody(req: IncomingMessage, limit: number): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] ?? 0);
    const tooBig = () => new HttpError(413, `body exceeds ${limit} bytes`);
    if (declared > limit) {
      // answer 413 and discard the upload without buffering it
      req.resume();
      reject(tooBig());
      return;
    }
    const chunks: Buffer[] = [];
    let n = 0;
    let over = false;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > limit) {
        over = true;
        if (n > limit * 8) req.destroy(); // chunked flood: stop listening
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => (over ? reject(tooBig()) : resolve(new Uint8Array(Buffer.concat(chunks)))));
    req.on("error", reject);
  });
}

const str = (v: unknown, max: number): v is string => typeof v === "string" && v.length <= max;

export function validateContext(doc: any): string | null {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return "context must be a JSON object";
  if (!str(doc.rationale, 4000) || !doc.rationale.trim()) return "rationale must be a non-empty string of at most 4000 characters";
  if (!Array.isArray(doc.evidence) || doc.evidence.length > 20) return "evidence must be an array of at most 20 items";
  for (const e of doc.evidence) if (!e || !str(e.label, 80) || !str(e.value, 500)) return "evidence items are {label ≤80, value ≤500}";
  if (doc.links !== undefined) {
    if (!Array.isArray(doc.links) || doc.links.length > 10) return "links must be an array of at most 10 items";
    for (const l of doc.links) if (!l || !str(l.label, 80) || !str(l.url, 500) || !/^https?:\/\//.test(l.url)) return "links are {label, http(s) url}";
  }
  const extra = Object.keys(doc).filter((k) => !["rationale", "evidence", "links"].includes(k));
  if (extra.length) return `unexpected fields: ${extra.join(", ")}`;
  return null;
}

export function validateReport(r: any): string | null {
  if (!r || typeof r !== "object") return "report must be an object";
  if (!str(r.resource_id, 63)) return "resource_id";
  if (!(r.request_id === null || (Number.isInteger(r.request_id) && r.request_id >= 0))) return "request_id";
  if (r.decision !== "allowed" && r.decision !== "denied") return "decision";
  if (!str(r.code, 40) || !/^[a-z_]+$/.test(r.code)) return "code";
  if (!str(r.program, 64)) return "program";
  if (!str(r.redacted_command, 200)) return "redacted_command";
  if (!str(r.command_sha256, 64) || !/^[0-9a-f]{64}$/.test(r.command_sha256)) return "command_sha256";
  if (!(r.action === null || str(r.action, 140))) return "action";
  if (!str(r.session, 64)) return "session";
  if (!(r.exit_code === null || Number.isInteger(r.exit_code))) return "exit_code";
  if (!(r.duration_ms === null || (Number.isInteger(r.duration_ms) && r.duration_ms >= 0))) return "duration_ms";
  if (!Number.isInteger(r.at_ms)) return "at_ms";
  return null;
}

export function createRelay(o: RelayOptions): { server: Server; close: () => void } {
  const now = o.now ?? Date.now;
  const auth = new RelayAuthenticator(o.resolver, { now });
  const log = o.log ?? (() => {});
  const sse = new Set<ServerResponse>();

  const broadcast = (event: string, data: unknown) => {
    const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of sse) res.write(frame);
  };

  const unsubscribe = o.watcher?.subscribe((c: RequestChange) => {
    broadcast("request", { id: c.id, state: c.state, previous: c.previous, agent_id: c.agent_id, resource_id: c.resource_id, action: c.action });
    if (c.state === "PendingApproval" && o.notifier && o.store.markNotified(c.id, now())) {
      o.notifier.pendingApproval({ request: c.request, consoleUrl: o.consoleUrl ?? null }).catch((e) => log(`notify failed for request ${c.id}: ${e instanceof Error ? e.message : e}`));
    }
  });

  const heartbeat = setInterval(() => {
    for (const res of sse) res.write(`: ping ${now()}\n\n`);
  }, 15_000);
  heartbeat.unref?.();

  const cors = (req: IncomingMessage, res: ServerResponse) => {
    const origin = req.headers.origin;
    const allowed = o.corsOrigins ?? [];
    if (origin && (allowed.includes("*") || allowed.includes(origin))) {
      res.setHeader("access-control-allow-origin", allowed.includes("*") ? "*" : origin);
      res.setHeader("vary", "origin");
      res.setHeader("access-control-allow-headers", "authorization, content-type");
      res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
      res.setHeader("access-control-max-age", "600");
    }
  };

  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  };

  const authed = (req: IncomingMessage, pathAndQuery: string, body: Uint8Array | undefined, roles: Role[]): Promise<Authenticated> =>
    auth.verify(req.headers.authorization, req.method ?? "GET", pathAndQuery, body, roles);

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    cors(req, res);
    const method = req.method ?? "GET";
    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    const pathAndQuery = req.url ?? "/";
    const url = new URL(pathAndQuery, "http://relay.local");
    const path = url.pathname;

    if (method === "GET" && path === "/v1/health") {
      let h: { chain_reachable: boolean; audit_seq: number | null } = { chain_reachable: false, audit_seq: null };
      try {
        h = o.health ? await o.health() : h;
      } catch {
        /* reported as unreachable */
      }
      return json(res, 200, { ok: true, contract: o.contractId, rpc: o.rpcUrl, ...h });
    }

    if (method === "POST" && path === "/v1/contexts") {
      const body = await readBody(req, MAX_CONTEXT_BYTES);
      const who = await authed(req, pathAndQuery, body, ["Agent"]);
      let doc: unknown;
      try {
        doc = JSON.parse(utf8.decode(body));
      } catch {
        throw new HttpError(400, "body is not JSON");
      }
      const err = validateContext(doc);
      if (err) throw new HttpError(400, err);
      const hash = hexEncode(await sha256(body));
      o.store.putContext(hash, who.binding.principal, body, now());
      return json(res, 201, { hash });
    }

    const ctx = /^\/v1\/contexts\/([0-9a-f]{64})$/.exec(path);
    if (method === "GET" && ctx) {
      await authed(req, pathAndQuery, undefined, READERS);
      const row = o.store.getContext(ctx[1]);
      if (!row) throw new HttpError(404, "no such context");
      return json(res, 200, { hash: row.hash, agent_id: row.agent_id, document: JSON.parse(utf8.decode(row.body)), created_at_ms: row.created_at_ms });
    }

    if (method === "POST" && path === "/v1/gate-reports") {
      const body = await readBody(req, MAX_REPORT_BYTES);
      const who = await authed(req, pathAndQuery, body, ["Gate"]);
      let r: any;
      try {
        r = JSON.parse(utf8.decode(body));
      } catch {
        throw new HttpError(400, "body is not JSON");
      }
      const err = validateReport(r);
      if (err) throw new HttpError(400, `invalid report field: ${err}`);
      if (r.resource_id !== who.binding.principal) throw new HttpError(403, `gate key belongs to ${who.binding.principal}, not ${r.resource_id}`);
      const report: GateReport = {
        resource_id: r.resource_id,
        request_id: r.request_id,
        decision: r.decision,
        code: r.code,
        program: r.program,
        redacted_command: r.redacted_command,
        command_sha256: r.command_sha256,
        action: r.action,
        session: r.session,
        exit_code: r.exit_code,
        duration_ms: r.duration_ms,
        at_ms: r.at_ms,
      };
      const id = o.store.addReport(report, now());
      broadcast("gate_report", { id, ...report });
      return json(res, 201, { id });
    }

    if (method === "GET" && path === "/v1/gate-reports") {
      await authed(req, pathAndQuery, undefined, READERS);
      const rid = url.searchParams.get("request_id");
      const reports = o.store.listReports({
        request_id: rid !== null && /^\d+$/.test(rid) ? Number(rid) : undefined,
        resource_id: url.searchParams.get("resource_id") ?? undefined,
        limit: Number(url.searchParams.get("limit") ?? 100) || 100,
      });
      return json(res, 200, { reports });
    }

    if (method === "GET" && path === "/v1/events") {
      // EventSource cannot set headers: the Authorization value travels in
      // `auth`, signed over the bare path.
      await auth.verify(url.searchParams.get("auth"), "GET", "/v1/events", undefined, READERS);
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive", "x-accel-buffering": "no" });
      res.write(`retry: 3000\n: connected ${now()}\n\n`);
      sse.add(res);
      req.on("close", () => sse.delete(res));
      return;
    }

    throw new HttpError(404, "not found");
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((e) => {
      const status = e instanceof AuthError || e instanceof HttpError ? e.status : 500;
      if (status === 500) log(`internal error on ${req.method} ${(req.url ?? "").split("?")[0]}: ${e instanceof Error ? e.message : e}`);
      if (!res.headersSent) json(res, status, { error: status === 500 ? "internal error" : e.message });
      else res.end();
    });
  });

  return {
    server,
    close: () => {
      clearInterval(heartbeat);
      unsubscribe?.();
      for (const r of sse) r.end();
      sse.clear();
      server.close();
    },
  };
}
