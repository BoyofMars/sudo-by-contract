// Client for the private relay (apps/relay). Every request is signed with a
// role key; the relay maps it to an on-chain identity via `whoami`.

import { utf8, type Signer } from "../../sbc-client/src/index.ts";
import { signRelayRequest } from "./relay-auth.ts";

export interface ContextDocument {
  rationale: string;
  evidence: Array<{ label: string; value: string }>;
  links?: Array<{ label: string; url: string }>;
}

export interface StoredContext {
  hash: string;
  agent_id: string;
  document: ContextDocument;
  created_at_ms: number;
}

export interface GateReport {
  resource_id: string;
  request_id: number | null;
  decision: "allowed" | "denied";
  code: string;
  program: string;
  redacted_command: string;
  command_sha256: string;
  action: string | null;
  session: string;
  exit_code: number | null;
  duration_ms: number | null;
  at_ms: number;
}

export class RelayError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "RelayError";
    this.status = status;
  }
}

export class RelayClient {
  baseUrl: string;
  signer: Signer;

  constructor(baseUrl: string, signer: Signer) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.signer = signer;
  }

  private async send<T>(method: string, pathAndQuery: string, body?: unknown): Promise<T> {
    const raw = body === undefined ? undefined : utf8.encode(JSON.stringify(body));
    const auth = await signRelayRequest(this.signer, method, pathAndQuery, raw);
    const res = await fetch(this.baseUrl + pathAndQuery, {
      method,
      headers: { authorization: auth, ...(raw ? { "content-type": "application/json" } : {}) },
      body: raw as BodyInit | undefined,
    });
    const text = await res.text();
    let j: any = null;
    try {
      j = text ? JSON.parse(text) : null;
    } catch {
      /* non-JSON error */
    }
    if (!res.ok) throw new RelayError(res.status, j?.error ?? (text || `relay HTTP ${res.status}`));
    return j as T;
  }

  /** Store a private context document; returns its sha256 (hex) for `context_hash`. */
  async postContext(doc: ContextDocument): Promise<string> {
    const r = await this.send<{ hash: string }>("POST", "/v1/contexts", doc);
    return r.hash;
  }

  getContext(hash: string): Promise<StoredContext> {
    return this.send("GET", `/v1/contexts/${encodeURIComponent(hash)}`);
  }

  postGateReport(report: GateReport): Promise<{ id: number }> {
    return this.send("POST", "/v1/gate-reports", report);
  }

  listGateReports(q: { request_id?: number; resource_id?: string; limit?: number } = {}): Promise<{ reports: Array<GateReport & { id: number }> }> {
    const p = new URLSearchParams();
    if (q.request_id !== undefined) p.set("request_id", String(q.request_id));
    if (q.resource_id) p.set("resource_id", q.resource_id);
    if (q.limit) p.set("limit", String(q.limit));
    const qs = p.toString();
    return this.send("GET", `/v1/gate-reports${qs ? "?" + qs : ""}`);
  }
}
