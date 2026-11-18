// NEAR AI Cloud as the model behind Act 3, verified rather than trusted.
//
// Before the first completion, the model's TEE attestation is fetched with a
// nonce generated here and checked: every NEAR model report must carry that
// nonce, its Intel TDX quote must verify (dcap-qvl, Intel PCS collateral), the
// quote's report data must bind the report's signing address and our nonce,
// its measured configuration and RTMR3 event log must match, and its NVIDIA
// GPU evidence must be judged genuine by NVIDIA's attestation service. If any
// of that fails, the act does not run the model. After each completion, its
// response signature is fetched and checked: the signed text must be the
// model id plus the SHA-256 of the exact request and response bytes, and the
// signer must be the attested key.
//
// This follows https://docs.near.ai/cloud/verification/ (model attestations;
// quote, nonce and signer bindings; response signatures) and NEAR's reference
// verifier, github.com/nearai/nearai-cloud-verifier (ts/model_verifier.ts,
// ts/chat_verifier.ts).

import { createHash, randomBytes } from "node:crypto";
// Values used only inside functions: llm-agent.ts imports this module too.
import { SYSTEM_PROMPT, TICKET, TOOL_SPECS, type ModelDriver, type ModelStep, type ToolCall } from "./llm-agent.ts";

export const NEARAI_BASE_URL = "https://cloud-api.near.ai";
/**
 * The default model. Of the models GET /v1/models listed on 2026-11-18, it is
 * one of the few owned by NEAR AI itself (so /v1/attestation/report with
 * provider=near returns NEAR model reports for it: TDX quote, GPU evidence and
 * an ECDSA signing key) that also supports tool calls; it is built for agentic
 * tool use, is the model NEAR's own verification docs use as their example,
 * and is cheap ($0.08 / $0.50 per million tokens). SBC_LLM_MODEL overrides it.
 */
export const NEARAI_MODEL = "z-ai/glm-5.3-flash";
export const INTEL_PCS_URL = "https://api.trustedservices.intel.com/tdx/certification/v4";
export const NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";
/** As NEAR's reference verifier: OutOfDate still means the quote's cryptography verified. */
const TCB_ACCEPTED = new Set(["UpToDate", "OutOfDate"]);

type Fetch = typeof fetch;

// ------------------------------------------------------------ attestation

export interface Check {
  name: "signer" | "nonce" | "model" | "tdx_quote" | "tdx_debug" | "report_data" | "mr_config" | "rtmr3" | "gpu";
  ok: boolean;
  detail: string;
}

/** The checks on one report: a model candidate, or the gateway. */
export interface ReportResult {
  kind: "model" | "gateway";
  index: number;
  signingAddress: string;
  signingAlgo: string;
  tcbStatus?: string;
  /** GPUs in the evidence NVIDIA's service judged, when the report carries GPU evidence */
  gpus?: number;
  gpuArch?: string;
  checks: Check[];
  ok: boolean;
}

export interface NearAiAttestation {
  model: string;
  /** 32 random bytes, hex, generated for this check only */
  nonce: string;
  checkedAt: string;
  durationMs: number;
  ok: boolean;
  /** why it failed */
  reason?: string;
  candidates: ReportResult[];
  gateway?: ReportResult;
  /** Distinct signing addresses of the model reports; set only when every report verified. */
  signingAddresses: string[];
}

/** What a verified TDX quote says, as hex strings. */
export interface VerifiedQuote {
  status: string;
  advisoryIds: string[];
  reportData: string;
  mrConfigId: string;
  rtMr3: string;
  tdAttributes: string;
}
export type QuoteVerifier = (quote: Uint8Array) => Promise<VerifiedQuote>;

/**
 * Intel DCAP quote verification with @phala/dcap-qvl-node (the library NEAR's
 * reference verifier uses). Collateral comes from Intel's PCS unless given.
 */
export function dcapQuoteVerifier(o: { pccsUrl?: string; collateral?: (quote: Uint8Array) => Promise<unknown>; nowSecs?: () => number; timeoutMs?: number } = {}): QuoteVerifier {
  return async (quote) => {
    const { js_get_collateral, js_verify } = await import("@phala/dcap-qvl-node");
    const collateral = o.collateral ? await o.collateral(quote) : await withTimeout(js_get_collateral(o.pccsUrl ?? INTEL_PCS_URL, quote), o.timeoutMs ?? 45_000, "Intel collateral");
    const now = o.nowSecs ? o.nowSecs() : Math.floor(Date.now() / 1000);
    const raw = js_verify(quote, collateral, BigInt(now)) as { status?: string; advisory_ids?: string[]; report?: Record<string, Record<string, string>> };
    const td = raw?.report?.TD10 ?? raw?.report?.TD15;
    if (!td) throw new Error(`not a TDX quote (${Object.keys(raw?.report ?? {}).join(", ") || "no report"})`);
    return {
      status: String(raw.status),
      advisoryIds: raw.advisory_ids ?? [],
      reportData: td.report_data,
      mrConfigId: td.mr_config_id,
      rtMr3: td.rt_mr3,
      tdAttributes: td.td_attributes,
    };
  };
}

/** The fields of a NEAR report this verifier reads. */
export interface NearReport {
  model_name?: string;
  signing_address?: string;
  signing_algo?: string;
  request_nonce?: string;
  intel_quote?: string;
  nvidia_payload?: string;
  event_log?: unknown;
  report_data?: string;
  tls_cert_fingerprint?: string;
  info?: { tcb_info?: unknown };
}

export interface AttestationOptions {
  fetch?: Fetch;
  baseUrl?: string;
  verifyQuote?: QuoteVerifier;
  nrasUrl?: string;
  timeoutMs?: number;
}

/**
 * Fetch the model's attestation with a fresh nonce and verify every NEAR model
 * report in it (and the gateway's report, when present). Never throws: a
 * failure is a result with ok: false and the reason.
 */
export async function verifyNearAiAttestation(model: string, opts: AttestationOptions = {}): Promise<NearAiAttestation> {
  const t0 = Date.now();
  const nonce = randomBytes(32).toString("hex");
  const out: NearAiAttestation = { model, nonce, checkedAt: new Date(t0).toISOString(), durationMs: 0, ok: false, candidates: [], signingAddresses: [] };
  const done = (reason?: string) => {
    out.ok = !reason;
    if (reason) out.reason = reason;
    out.durationMs = Date.now() - t0;
    return out;
  };
  const f = opts.fetch ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 60_000;

  let body: { model_attestations?: NearReport[]; gateway_attestation?: NearReport };
  try {
    const q = new URLSearchParams({ model, provider: "near", signing_algo: "ecdsa", include_tls_fingerprint: "false", nonce });
    // no API key: the report is public, and it is checked before any credential is sent
    const res = await f(`${(opts.baseUrl ?? NEARAI_BASE_URL).replace(/\/+$/, "")}/v1/attestation/report?${q}`, {
      headers: { accept: "application/json", "x-no-aliasing": "true" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return done(`the attestation report request failed: HTTP ${res.status} ${(await res.text()).slice(0, 160)}`);
    body = (await res.json()) as typeof body;
  } catch (e) {
    return done(`the attestation report could not be fetched: ${message(e)}`);
  }

  const reports = body?.model_attestations;
  if (!Array.isArray(reports) || reports.length === 0) return done("the report carries no NEAR model attestation (model_attestations[] is missing or empty)");

  const deps = { verifyQuote: opts.verifyQuote ?? dcapQuoteVerifier(), fetch: f, nrasUrl: opts.nrasUrl ?? NRAS_URL, timeoutMs };
  let candidates: ReportResult[];
  let gateway: ReportResult | undefined;
  try {
    [candidates, gateway] = await Promise.all([
      Promise.all(reports.map((r, i) => checkNearReport(r, nonce, { ...deps, kind: "model", index: i, model }))),
      body.gateway_attestation ? checkNearReport(body.gateway_attestation, nonce, { ...deps, kind: "gateway", index: 0 }) : Promise.resolve(undefined),
    ]);
  } catch (e) {
    return done(`the attestation could not be checked: ${message(e)}`);
  }
  out.candidates = candidates;
  if (gateway) out.gateway = gateway;

  const failed = [...candidates, ...(gateway ? [gateway] : [])].filter((c) => !c.ok);
  if (failed.length) {
    return done(failed.map((c) => `${reportLabel(c)}: ${c.checks.filter((x) => !x.ok).map((x) => `${x.name} (${x.detail})`).join(", ")}`).join("; "));
  }
  out.signingAddresses = [...new Map(candidates.map((c) => [c.signingAddress.toLowerCase(), c.signingAddress])).values()];
  return done();
}

export const reportLabel = (r: ReportResult) => (r.kind === "gateway" ? "gateway" : `model report #${r.index + 1}`);

/** Every check the NEAR docs list for one report, each recorded with its outcome. */
export async function checkNearReport(
  report: NearReport,
  nonce: string,
  d: { kind: "model" | "gateway"; index: number; model?: string; verifyQuote: QuoteVerifier; fetch: Fetch; nrasUrl: string; timeoutMs?: number },
): Promise<ReportResult> {
  const checks: Check[] = [];
  const add = (name: Check["name"], ok: boolean, detail: string) => void checks.push({ name, ok, detail });
  const r: ReportResult = { kind: d.kind, index: d.index, signingAddress: String(report?.signing_address ?? ""), signingAlgo: String(report?.signing_algo ?? ""), checks, ok: false };
  const finish = () => {
    r.ok = checks.length > 0 && checks.every((c) => c.ok);
    return r;
  };

  // the signing identity: an ECDSA (Ethereum-style) address, as requested
  let identity: Buffer | undefined;
  try {
    if (r.signingAlgo !== "ecdsa") throw new Error(`signing_algo is ${r.signingAlgo || "missing"}; ecdsa was requested`);
    identity = hexBytes(r.signingAddress, "signing_address", 20);
    add("signer", true, r.signingAddress);
  } catch (e) {
    add("signer", false, message(e));
  }

  // (a) the report echoes our nonce
  const echoed = String(report?.request_nonce ?? "").toLowerCase();
  add("nonce", echoed === nonce, echoed === nonce ? "request_nonce is ours" : `request_nonce ${echoed ? echoed.slice(0, 16) + "…" : "missing"} is not the nonce we sent`);
  if (d.model && report?.model_name !== undefined) add("model", report.model_name === d.model, report.model_name === d.model ? report.model_name : `report is for ${report.model_name}`);

  // (b) the Intel TDX quote verifies
  let q: VerifiedQuote;
  try {
    q = await d.verifyQuote(hexBytes(String(report?.intel_quote ?? ""), "intel_quote"));
  } catch (e) {
    add("tdx_quote", false, `did not verify: ${message(e)}`);
    return finish();
  }
  r.tcbStatus = q.status;
  add("tdx_quote", TCB_ACCEPTED.has(q.status), `${q.status}${q.advisoryIds.length ? ` · advisories ${q.advisoryIds.join(", ")}` : ""}`);
  try {
    const debug = (hexBytes(q.tdAttributes, "td_attributes")[0] & 1) === 1;
    add("tdx_debug", !debug, debug ? "the TD runs in debug mode" : "not in debug mode");
  } catch (e) {
    add("tdx_debug", false, message(e));
  }

  // (c) the quote's report data binds the signer and our nonce:
  // [0..32] = signing address right-padded to 32 bytes (or, with TLS binding,
  // SHA-256(address || fingerprint)); [32..64] = the raw nonce
  try {
    const rd = hexBytes(q.reportData, "report_data", 64);
    const problems: string[] = [];
    if (identity) {
      const fp = report.tls_cert_fingerprint;
      const bound = fp ? sha256(identity, hexBytes(fp, "tls_cert_fingerprint", 32)) : Buffer.concat([identity, Buffer.alloc(32 - identity.length)]);
      if (!rd.subarray(0, 32).equals(bound)) problems.push("it does not bind the signing address");
    } else problems.push("no valid signing address to bind");
    if (!rd.subarray(32, 64).equals(Buffer.from(nonce, "hex"))) problems.push("it does not carry our nonce");
    if (report.report_data !== undefined && !hexBytes(report.report_data, "report_data field").equals(rd)) problems.push("the report_data field differs from the quote's");
    add("report_data", problems.length === 0, problems.length ? problems.join("; ") : "binds the signing address and our nonce");
  } catch (e) {
    add("report_data", false, message(e));
  }

  // the measured configuration: MRCONFIGID = 01 || SHA-256(app_compose) || 15 zero bytes
  try {
    const tcb = parseMaybe(report.info?.tcb_info) as { app_compose?: unknown } | undefined;
    if (typeof tcb?.app_compose !== "string") throw new Error("no app_compose in tcb_info");
    const composeHash = sha256(Buffer.from(tcb.app_compose, "utf8"));
    const matches = hexBytes(q.mrConfigId, "mr_config_id").equals(Buffer.concat([Buffer.from([1]), composeHash, Buffer.alloc(15)]));
    add("mr_config", matches, matches ? `app_compose sha256 ${composeHash.toString("hex").slice(0, 16)}…` : "MRCONFIGID does not match app_compose");
  } catch (e) {
    add("mr_config", false, message(e));
  }

  // the runtime event log replays to the quote's RTMR3
  try {
    const matches = replayRtmr3(report.event_log).equals(hexBytes(q.rtMr3, "rt_mr3", 48));
    add("rtmr3", matches, matches ? "event log replays to the quote's RTMR3" : "event log does not replay to RTMR3");
  } catch (e) {
    add("rtmr3", false, message(e));
  }

  // (d) GPU evidence, when present: same nonce, and NVIDIA's verdict is true
  if (report.nvidia_payload != null) {
    try {
      const raw = typeof report.nvidia_payload === "string" ? report.nvidia_payload : JSON.stringify(report.nvidia_payload);
      const p = JSON.parse(raw) as { nonce?: unknown; arch?: string; evidence_list?: unknown[] };
      if (typeof p.nonce !== "string" || p.nonce.toLowerCase() !== nonce) throw new Error("the GPU evidence carries another nonce (not sent to NVIDIA)");
      r.gpus = Array.isArray(p.evidence_list) ? p.evidence_list.length : undefined;
      r.gpuArch = p.arch;
      const res = await d.fetch(d.nrasUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: raw,
        signal: AbortSignal.timeout(d.timeoutMs ?? 60_000),
      });
      const text = await res.text();
      if (!res.ok) throw new Error(`NVIDIA NRAS HTTP ${res.status} ${text.slice(0, 120)}`);
      const answer = JSON.parse(text) as unknown;
      const jwt = Array.isArray(answer) && Array.isArray(answer[0]) && answer[0][0] === "JWT" ? String(answer[0][1]) : undefined;
      if (!jwt) throw new Error("NVIDIA NRAS returned no JWT");
      const claims = jwtClaims(jwt);
      const verdict = claims["x-nvidia-overall-att-result"];
      const eatNonce = claims.eat_nonce;
      if (eatNonce !== undefined && String(eatNonce).toLowerCase() !== nonce) throw new Error("NVIDIA's token is for another nonce");
      add("gpu", verdict === true, verdict === true ? `NVIDIA NRAS verdict true · ${r.gpus ?? "?"} × ${r.gpuArch ?? "GPU"}` : `NVIDIA NRAS verdict ${JSON.stringify(verdict)}`);
    } catch (e) {
      add("gpu", false, message(e));
    }
  }
  return finish();
}

/** RTMR3 from the event log: SHA-384 extend of each IMR-3 event's digest, from 48 zero bytes. */
export function replayRtmr3(eventLog: unknown): Buffer {
  const events = parseMaybe(eventLog);
  if (!Array.isArray(events)) throw new Error("no event log");
  let rtmr3 = Buffer.alloc(48);
  for (const ev of events as Array<{ imr?: number; event_type?: number; event?: string; event_payload?: string; digest?: string }>) {
    if (ev?.imr !== 3) continue;
    const type = Buffer.alloc(4);
    type.writeUInt32LE(Number(ev.event_type));
    const digest = createHash("sha384")
      .update(type)
      .update(":")
      .update(Buffer.from(String(ev.event ?? ""), "utf8"))
      .update(":")
      .update(hexBytes(String(ev.event_payload ?? ""), "event_payload"))
      .digest();
    if (ev.digest && !hexBytes(ev.digest, "digest").equals(digest)) throw new Error(`event ${ev.event}: digest does not match its payload`);
    rtmr3 = createHash("sha384").update(rtmr3).update(digest).digest();
  }
  return rtmr3;
}

// ---------------------------------------------------- response signatures

/** GET /v1/signature/{id}: a signature, or an "unavailable" result (error_code + message). */
export interface SignaturePayload {
  text?: string;
  signature?: string;
  signing_address?: string;
  signing_algo?: string;
  signature_kind?: string | null;
  error_code?: string;
  message?: string;
}

export interface ReplySignature {
  ok: boolean;
  kind?: string;
  signer?: string;
  detail: string;
}

/**
 * Check a reply's signature: the signed text is exactly what the exact bytes
 * imply, the ECDSA (EIP-191) signer recovers to signing_address, and that
 * address is the key of the attested model reports (provider_tee) or of the
 * attested gateway (gateway).
 */
export async function checkReplySignature(sig: SignaturePayload | undefined, x: { model: string; requestHash: string; responseHash: string }, att: NearAiAttestation): Promise<ReplySignature> {
  const no = (detail: string, extra: Partial<ReplySignature> = {}): ReplySignature => ({ ok: false, detail, ...extra });
  if (!att.ok) return no("there is no verified attestation to match it against");
  if (!sig || typeof sig.text !== "string" || typeof sig.signature !== "string") return no(sig?.error_code ? `unavailable: ${sig.error_code} ${sig.message ?? ""}`.trim() : "no signature returned");
  const kind = sig.signature_kind ?? undefined;
  if (kind !== "provider_tee" && kind !== "gateway") return no(`signature_kind is ${kind ? `"${kind}"` : "missing"}, so the signer cannot be classified`);
  const expected = kind === "provider_tee" ? `${x.model}:${x.requestHash}:${x.responseHash}` : `${x.requestHash}:${x.responseHash}`;
  if (sig.text !== expected) {
    const parts = sig.text.split(":");
    const [m, rq, rs] = parts.length === 3 ? parts : [undefined, parts[0], parts[1]];
    const why = [m !== undefined && m !== x.model && "model id", rq !== x.requestHash && "request hash", rs !== x.responseHash && "response hash"].filter(Boolean).join(", ");
    return no(`the signed text does not match the exact bytes (${why || "format"})`, { kind });
  }
  if (sig.signing_algo !== "ecdsa") return no(`signing_algo is ${sig.signing_algo ?? "missing"}; ecdsa was requested`, { kind });
  let claimed: Buffer;
  let recovered: string;
  try {
    claimed = hexBytes(String(sig.signing_address ?? ""), "signing_address", 20);
    const { verifyMessage, hexlify } = await import("ethers");
    recovered = verifyMessage(sig.text, hexlify(hexBytes(sig.signature, "signature", 65)));
  } catch (e) {
    return no(`the signature does not parse: ${message(e)}`, { kind });
  }
  if (!hexBytes(recovered, "recovered signer", 20).equals(claimed)) return no(`the signature recovers to ${recovered}, not to signing_address ${sig.signing_address}`, { kind, signer: recovered });

  const lc = recovered.toLowerCase();
  if (kind === "provider_tee") {
    // all model reports verified; instances of one model share one key
    const matching = att.signingAddresses.filter((a) => a.toLowerCase() === lc);
    if (matching.length !== 1) return no(`signer ${recovered} is not the attested model key (${att.signingAddresses.join(", ") || "none"})`, { kind, signer: recovered });
    return { ok: true, kind, signer: recovered, detail: "model TEE signature over the exact request and response" };
  }
  if (!att.gateway?.ok || att.gateway.signingAddress.toLowerCase() !== lc) return no(`signer ${recovered} is not the attested gateway key`, { kind, signer: recovered });
  return { ok: true, kind, signer: recovered, detail: "gateway TEE signature over the exact bytes received (it does not by itself prove the model ran in a TEE)" };
}

// ------------------------------------------------------------------ driver

interface ChatToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}
type ChatMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string; tool_calls?: ChatToolCall[] }
  | { role: "tool"; tool_call_id: string; content: string };
interface ChatCompletion {
  id?: string;
  choices?: Array<{
    finish_reason?: string | null;
    message?: { content?: string | null; reasoning_content?: string | null; reasoning?: string | null; refusal?: string | null; tool_calls?: Array<Partial<ChatToolCall>> | null };
  }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

export interface NearAiDriverOptions {
  apiKey: string;
  model?: string;
  baseUrl?: string;
  fetch?: Fetch;
  /** The preflight attestation; by default verifyNearAiAttestation through the same fetch. */
  attest?: (model: string) => Promise<NearAiAttestation>;
  maxTokens?: number;
  timeoutMs?: number;
  /** how often to ask again for a signature not recorded yet (404) */
  signatureAttempts?: number;
  retryDelayMs?: number;
}

export class AttestationRefused extends Error {
  constructor(reason: string | undefined) {
    super(`NEAR AI TEE attestation did not verify, so nothing is sent to the model: ${reason ?? "unknown reason"}`);
    this.name = "AttestationRefused";
  }
}

/**
 * NEAR AI Cloud's OpenAI-compatible chat completions, stateless (the full
 * history goes every turn). The model is attested before the first request,
 * and each reply's signature is checked.
 */
export function nearAiDriver(o: NearAiDriverOptions): ModelDriver {
  const model = o.model || NEARAI_MODEL;
  const base = (o.baseUrl ?? NEARAI_BASE_URL).replace(/\/+$/, "");
  const f = o.fetch ?? fetch;
  const delay = o.retryDelayMs ?? 1_500;
  const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const messages: ChatMessage[] = [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: TICKET },
  ];
  const tools = TOOL_SPECS.map((t) => ({ type: "function" as const, function: { name: t.name, description: t.description, parameters: t.schema } }));
  const headers = {
    authorization: `Bearer ${o.apiKey}`,
    "content-type": "application/json",
    accept: "application/json",
    // the canonical model id is part of the signed text: never let the gateway rewrite it
    "x-no-aliasing": "true",
  };
  let preflight: Promise<NearAiAttestation> | undefined;
  const attest = () => (preflight ??= (o.attest ?? ((m: string) => verifyNearAiAttestation(m, { fetch: f, baseUrl: base })))(model));
  let turn = 0;

  async function signature(id: string | undefined, requestHash: string, responseHash: string, att: NearAiAttestation): Promise<ReplySignature> {
    if (!id) return { ok: false, detail: "the completion has no id to fetch a signature for" };
    const url = `${base}/v1/signature/${encodeURIComponent(id)}?${new URLSearchParams({ model, signing_algo: "ecdsa" })}`;
    const attempts = o.signatureAttempts ?? 4;
    for (let i = 1; ; i++) {
      try {
        const res = await f(url, { headers: { authorization: headers.authorization, accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
        if (res.status === 404 && i < attempts) {
          await pause(delay); // not recorded yet: a short, bounded wait
          continue;
        }
        if (!res.ok) return { ok: false, detail: `no signature: HTTP ${res.status}` };
        return await checkReplySignature((await res.json()) as SignaturePayload, { model, requestHash, responseHash }, att);
      } catch (e) {
        if (i < attempts) {
          await pause(delay);
          continue;
        }
        return { ok: false, detail: `the signature could not be fetched: ${message(e)}` };
      }
    }
  }

  return {
    provider: "nearai",
    model,
    attest,
    async next(outcomes) {
      const att = await attest();
      if (!att.ok) throw new AttestationRefused(att.reason); // fail closed, even if the caller skipped the preflight
      for (const x of outcomes) messages.push({ role: "tool", tool_call_id: x.call.id, content: x.content });

      // these exact bytes are what the request hash in the signed text covers
      const body = JSON.stringify({ model, messages, tools, tool_choice: "auto", max_tokens: o.maxTokens ?? 8192, stream: false });
      const notes: string[] = [];
      let bytes: Buffer;
      for (let attempt = 1; ; attempt++) {
        try {
          const res = await f(`${base}/v1/chat/completions`, { method: "POST", headers, body, signal: AbortSignal.timeout(o.timeoutMs ?? 120_000) });
          bytes = Buffer.from(await res.arrayBuffer()); // the exact (decompressed) response bytes
          if (!res.ok) throw Object.assign(new Error(`NEAR AI Cloud HTTP ${res.status}: ${bytes.toString("utf8").slice(0, 200)}`), { status: res.status });
          break;
        } catch (e) {
          if (attempt === 1 && retryable(e)) {
            notes.push(`${model} unavailable (${message(e).slice(0, 120)}); retrying once`);
            await pause(5_000);
            continue;
          }
          throw e;
        }
      }
      const res = JSON.parse(bytes.toString("utf8")) as ChatCompletion;
      const choice = res.choices?.[0];
      const m = choice?.message ?? {};
      turn++;
      const calls: ToolCall[] = [];
      const sent: ChatToolCall[] = [];
      for (const [i, tc] of (m.tool_calls ?? []).entries()) {
        const id = tc.id || `call_${turn}_${i}`;
        const name = String(tc.function?.name ?? "");
        const args = String(tc.function?.arguments ?? "");
        let input: Record<string, unknown> = {};
        try {
          input = args.trim() ? (JSON.parse(args) as Record<string, unknown>) : {};
        } catch {
          notes.push(`the arguments of ${name} were not valid JSON`);
        }
        calls.push({ id, name, input });
        sent.push({ id, type: "function", function: { name, arguments: args } });
      }
      messages.push({ role: "assistant", content: m.content ?? "", ...(sent.length ? { tool_calls: sent } : {}) });

      const s: ModelStep = {
        thinking: [m.reasoning_content ?? m.reasoning ?? ""].map((t) => t.trim()).filter(Boolean),
        text: [m.content ?? ""].map((t) => t.trim()).filter(Boolean),
        calls,
        stop: "end_turn",
        notes,
        inputTokens: res.usage?.prompt_tokens ?? 0,
        outputTokens: res.usage?.completion_tokens ?? 0,
        signature: await signature(res.id, sha256(Buffer.from(body, "utf8")).toString("hex"), sha256(bytes).toString("hex"), att),
      };
      const finish = choice?.finish_reason;
      if (!choice) {
        s.stop = "error";
        s.detail = "the completion has no choices";
      } else if (finish === "content_filter" || m.refusal) {
        s.stop = "refusal";
        s.detail = m.refusal ?? finish ?? undefined;
      } else if (calls.length) s.stop = "tool_use";
      else if (finish === "length") s.stop = "max_tokens";
      return s;
    },
  };
}

// ----------------------------------------------------------------- helpers

function message(e: unknown): string {
  return (e instanceof Error ? e.message : String(e)).split("\n")[0].slice(0, 200);
}

function retryable(e: unknown): boolean {
  const x = e as { status?: number; name?: string; message?: string };
  return x.status === 429 || (x.status !== undefined && x.status >= 500) || /timeout|timed out|aborted|fetch failed/i.test(`${x.name ?? ""} ${x.message ?? ""}`);
}

function sha256(...parts: Uint8Array[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

/** Strict hex decoding (Buffer.from silently drops what is not hex). */
function hexBytes(value: string, label: string, length?: number): Buffer {
  const hex = String(value ?? "").replace(/^0x/i, "");
  if (hex.length % 2 || !/^[0-9a-f]*$/i.test(hex)) throw new Error(`${label} is not hex`);
  const b = Buffer.from(hex, "hex");
  if (length !== undefined && b.length !== length) throw new Error(`${label} is ${b.length} bytes, expected ${length}`);
  return b;
}

function parseMaybe(v: unknown): unknown {
  return typeof v === "string" ? JSON.parse(v) : v;
}

function jwtClaims(jwt: string): Record<string, unknown> {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("malformed JWT");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    p.finally(() => clearTimeout(timer)),
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms / 1000} s`)), ms);
    }),
  ]);
}
