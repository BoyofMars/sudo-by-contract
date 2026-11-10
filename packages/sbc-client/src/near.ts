// Minimal NEAR JSON-RPC client: view calls, access-key nonces, and signed
// FunctionCall transactions encoded with borsh by hand. Small enough to audit,
// with no wallet or SDK dependency, and identical in the browser and Node.

import { b64decode, b64encode, base58Decode, concat, utf8 } from "./encoding.ts";
import { sha256, type Signer, publicKeyToString } from "./keys.ts";

export const DEFAULT_TESTNET_RPC = "https://rpc.testnet.fastnear.com";
export const TGAS = 1_000_000_000_000n;

export class RpcError extends Error {
  data: unknown;
  constructor(message: string, data?: unknown) {
    super(message);
    this.name = "RpcError";
    this.data = data;
  }
}

/** A transaction executed but the contract panicked or the receipt failed. */
export class ExecutionError extends Error {
  failure: unknown;
  txHash: string;
  constructor(message: string, failure: unknown, txHash: string) {
    super(message);
    this.name = "ExecutionError";
    this.failure = failure;
    this.txHash = txHash;
  }
}

// ------------------------------------------------------------------- borsh

class BorshWriter {
  private parts: Uint8Array[] = [];
  u8(v: number) {
    this.parts.push(new Uint8Array([v]));
  }
  u32(v: number) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v, true);
    this.parts.push(b);
  }
  u64(v: bigint) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v, true);
    this.parts.push(b);
  }
  u128(v: bigint) {
    const b = new Uint8Array(16);
    const dv = new DataView(b.buffer);
    dv.setBigUint64(0, v & 0xffff_ffff_ffff_ffffn, true);
    dv.setBigUint64(8, v >> 64n, true);
    this.parts.push(b);
  }
  fixed(b: Uint8Array) {
    this.parts.push(b);
  }
  bytes(b: Uint8Array) {
    this.u32(b.length);
    this.parts.push(b);
  }
  string(s: string) {
    this.bytes(utf8.encode(s));
  }
  done(): Uint8Array {
    return concat(...this.parts);
  }
}

export interface FunctionCallAction {
  methodName: string;
  args: Uint8Array;
  gas: bigint;
  deposit: bigint;
}

export function encodeTransaction(tx: {
  signerId: string;
  publicKey: Uint8Array;
  nonce: bigint;
  receiverId: string;
  blockHash: Uint8Array;
  actions: FunctionCallAction[];
}): Uint8Array {
  const w = new BorshWriter();
  w.string(tx.signerId);
  w.u8(0); // KeyType::ED25519
  w.fixed(tx.publicKey);
  w.u64(tx.nonce);
  w.string(tx.receiverId);
  w.fixed(tx.blockHash);
  w.u32(tx.actions.length);
  for (const a of tx.actions) {
    w.u8(2); // Action::FunctionCall
    w.string(a.methodName);
    w.bytes(a.args);
    w.u64(a.gas);
    w.u128(a.deposit);
  }
  return w.done();
}

export function encodeSignedTransaction(txBytes: Uint8Array, signature: Uint8Array): Uint8Array {
  const w = new BorshWriter();
  w.fixed(txBytes);
  w.u8(0);
  w.fixed(signature);
  return w.done();
}

// --------------------------------------------------------------------- rpc

export type WaitUntil = "INCLUDED" | "INCLUDED_FINAL" | "EXECUTED_OPTIMISTIC" | "EXECUTED" | "FINAL";

export interface TxOutcome {
  txHash: string;
  /** Parsed JSON return value of the called method, if any. */
  value: unknown;
  raw: any;
}

export class NearRpc {
  url: string;
  private id = 0;
  constructor(url: string = DEFAULT_TESTNET_RPC) {
    this.url = url;
  }

  async call<T = any>(method: string, params: unknown): Promise<T> {
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: String(++this.id), method, params }),
    });
    if (!res.ok) throw new RpcError(`RPC HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) {
      const cause = j.error?.cause?.name ?? j.error?.name ?? "RPC_ERROR";
      throw new RpcError(`${cause}: ${JSON.stringify(j.error?.data ?? j.error?.cause?.info ?? j.error).slice(0, 400)}`, j.error);
    }
    return j.result as T;
  }

  async view<T = any>(contractId: string, method: string, args: unknown = {}): Promise<T> {
    const r = await this.call("query", {
      request_type: "call_function",
      finality: "optimistic",
      account_id: contractId,
      method_name: method,
      args_base64: b64encode(utf8.encode(JSON.stringify(args))),
    });
    if (r.error) throw new RpcError(String(r.error), r);
    const text = utf8.decode(new Uint8Array(r.result));
    return (text ? JSON.parse(text) : null) as T;
  }

  async accessKey(accountId: string, publicKey: Uint8Array): Promise<{ nonce: bigint; blockHash: Uint8Array; permission: any } | null> {
    try {
      const r = await this.call("query", {
        request_type: "view_access_key",
        finality: "optimistic",
        account_id: accountId,
        public_key: publicKeyToString(publicKey),
      });
      return { nonce: BigInt(r.nonce), blockHash: base58Decode(r.block_hash), permission: r.permission };
    } catch (e) {
      if (e instanceof RpcError && /UNKNOWN_ACCESS_KEY|does not exist/i.test(e.message)) return null;
      throw e;
    }
  }

  async functionCall(
    signer: Signer,
    receiverId: string,
    methodName: string,
    args: unknown,
    opts: { gas?: bigint; deposit?: bigint; waitUntil?: WaitUntil } = {},
  ): Promise<TxOutcome> {
    const argsBytes = utf8.encode(JSON.stringify(args));
    for (let attempt = 0; ; attempt++) {
      const ak = await this.accessKey(signer.accountId, signer.publicKey);
      if (!ak) throw new RpcError(`access key ${publicKeyToString(signer.publicKey)} is not on ${signer.accountId} (not enrolled, or removed)`);
      const tx = encodeTransaction({
        signerId: signer.accountId,
        publicKey: signer.publicKey,
        nonce: ak.nonce + 1n + BigInt(attempt),
        receiverId,
        blockHash: ak.blockHash,
        actions: [{ methodName, args: argsBytes, gas: opts.gas ?? 100n * TGAS, deposit: opts.deposit ?? 0n }],
      });
      const hash = await sha256(tx);
      const sig = await signer.sign(hash);
      const signed = encodeSignedTransaction(tx, sig);
      try {
        const r = await this.call("send_tx", {
          signed_tx_base64: b64encode(signed),
          wait_until: opts.waitUntil ?? "EXECUTED_OPTIMISTIC",
        });
        return interpretOutcome(r);
      } catch (e) {
        // concurrent use of the same key: retry with a fresh nonce
        if (attempt < 3 && e instanceof RpcError && /InvalidNonce|nonce/i.test(e.message)) continue;
        throw e;
      }
    }
  }
}

function interpretOutcome(r: any): TxOutcome {
  const txHash: string = r?.transaction?.hash ?? r?.transaction_outcome?.id ?? "";
  const status = r?.status;
  if (status && typeof status === "object" && "Failure" in status) {
    throw new ExecutionError(describeFailure(status.Failure), status.Failure, txHash);
  }
  // A panic inside the first receipt shows up in receipts_outcome, too.
  for (const ro of r?.receipts_outcome ?? []) {
    const s = ro?.outcome?.status;
    if (s && typeof s === "object" && "Failure" in s && ro?.outcome?.executor_id === r?.transaction?.receiver_id) {
      throw new ExecutionError(describeFailure(s.Failure), s.Failure, txHash);
    }
  }
  let value: unknown = undefined;
  if (status && typeof status === "object" && typeof status.SuccessValue === "string" && status.SuccessValue.length) {
    const text = utf8.decode(b64decode(status.SuccessValue));
    try {
      value = JSON.parse(text);
    } catch {
      value = text;
    }
  }
  return { txHash, value, raw: r };
}

export function describeFailure(f: any): string {
  const exec = f?.ActionError?.kind?.FunctionCallError?.ExecutionError;
  if (typeof exec === "string") return exec.replace(/^Smart contract panicked: /, "");
  return JSON.stringify(f).slice(0, 300);
}
