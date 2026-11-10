// Client for the private relay (off-chain context documents, redacted gate
// reports, live events). Requests are signed with the device key:
//
//   Authorization: SBC-Ed25519 pk=<ed25519:base58>,ts=<unix ms>,sig=<base64>
//   sig = Ed25519( "sbc-relay/v1\n" + METHOD + "\n" + PATH_AND_QUERY + "\n" + ts + "\n" + sha256hex(body) )
//
// where body is the request body bytes (empty for GET, so sha256 of "").

import { b64encode, hexEncode, publicKeyToString, sha256, utf8, type Signer } from "@sbc/client";

export interface ContextDocument {
  rationale: string;
  evidence: { label: string; value: string }[];
  links?: { label: string; url: string }[];
}

export interface ContextRecord {
  hash: string;
  agent_id: string;
  document: ContextDocument;
  created_at_ms: number;
  /** Optional: the exact bytes that were hashed, if the relay returns them. */
  raw?: string;
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

export type RelayEvent =
  | { type: "request"; id: number; state: string }
  | { type: "gate_report"; report: GateReport };

export async function signRelayRequest(signer: Signer, method: string, pathAndQuery: string, body: Uint8Array = new Uint8Array()): Promise<string> {
  const ts = Date.now();
  const bodyHash = hexEncode(await sha256(body));
  const msg = `sbc-relay/v1\n${method.toUpperCase()}\n${pathAndQuery}\n${ts}\n${bodyHash}`;
  const sig = await signer.sign(utf8.encode(msg));
  return `SBC-Ed25519 pk=${publicKeyToString(signer.publicKey)},ts=${ts},sig=${b64encode(sig)}`;
}

export class RelayClient {
  base: string;
  signer: Signer | null;

  constructor(base: string, signer: Signer | null) {
    this.base = base.replace(/\/+$/, "");
    this.signer = signer;
  }

  private async get<T>(pathAndQuery: string, auth = true): Promise<T> {
    const headers: Record<string, string> = {};
    if (auth) {
      if (!this.signer) throw new Error("no device key");
      headers.authorization = await signRelayRequest(this.signer, "GET", pathAndQuery);
    }
    const res = await fetch(this.base + pathAndQuery, { headers });
    if (res.status === 404) throw Object.assign(new Error("not found"), { status: 404 });
    if (!res.ok) throw Object.assign(new Error(`relay HTTP ${res.status}`), { status: res.status });
    return (await res.json()) as T;
  }

  async health(): Promise<boolean> {
    try {
      const r = await fetch(this.base + "/v1/health", { signal: AbortSignal.timeout(4000) });
      return r.ok;
    } catch {
      return false;
    }
  }

  context(hash: string) {
    return this.get<ContextRecord>(`/v1/contexts/${hash}`);
  }

  gateReports(q: { request_id?: number; resource_id?: string; limit?: number }) {
    const p = new URLSearchParams();
    if (q.request_id !== undefined) p.set("request_id", String(q.request_id));
    if (q.resource_id) p.set("resource_id", q.resource_id);
    p.set("limit", String(q.limit ?? 50));
    return this.get<GateReport[]>(`/v1/gate-reports?${p.toString()}`);
  }

  /** Server-sent events. EventSource cannot set headers, so auth rides in the query. */
  async subscribe(onEvent: (e: RelayEvent) => void): Promise<() => void> {
    if (!this.signer) return () => {};
    const auth = await signRelayRequest(this.signer, "GET", "/v1/events");
    const es = new EventSource(`${this.base}/v1/events?auth=${encodeURIComponent(auth)}`);
    es.addEventListener("request", (m) => {
      try {
        const d = JSON.parse((m as MessageEvent).data);
        onEvent({ type: "request", id: d.id, state: d.state });
      } catch {
        /* ignore */
      }
    });
    es.addEventListener("gate_report", (m) => {
      try {
        onEvent({ type: "gate_report", report: JSON.parse((m as MessageEvent).data) });
      } catch {
        /* ignore */
      }
    });
    return () => es.close();
  }
}

/** Does the document the relay returned match the hash committed on-chain? */
export async function verifyContext(rec: ContextRecord, onChainHash: string): Promise<boolean> {
  const candidates = [rec.raw, JSON.stringify(rec.document)].filter((x): x is string => typeof x === "string");
  for (const c of candidates) {
    if (hexEncode(await sha256(utf8.encode(c))) === onChainHash.toLowerCase()) return true;
  }
  return false;
}
