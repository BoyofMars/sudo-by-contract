// The gate's decision logic, in the browser.
//
// `sbc_core.wasm` is crates/sbc-wasm: the same `sbc-core` crate that `sbc-gate`
// runs on enrolled hosts, compiled to WebAssembly (no wasm-bindgen; see the
// crate for the 3-function ABI). Rebuild with `npm run build:wasm`.

import wasmUrl from "../wasm/sbc_core.wasm?url";

export type GateVerdict =
  | {
      ok: true;
      action: string;
      kind: string;
      target: string;
      describe: string;
      read_only: boolean;
      via_sudo: boolean;
      log_lines: number;
      argv_systemd: string[];
      argv_supervisor: string[];
      program: string;
      redacted: string;
    }
  | { ok: false; code: string; message: string; program: string; redacted: string };

interface Exports {
  memory: WebAssembly.Memory;
  alloc(len: number): number;
  dealloc(ptr: number, len: number): void;
  evaluate(ptr: number, len: number): bigint;
}

let loading: Promise<(command: string) => GateVerdict> | null = null;

async function instantiate(): Promise<WebAssembly.Instance> {
  try {
    const { instance } = await WebAssembly.instantiateStreaming(fetch(wasmUrl), {});
    return instance;
  } catch {
    // servers that do not send application/wasm
    const bytes = await (await fetch(wasmUrl)).arrayBuffer();
    return (await WebAssembly.instantiate(bytes, {})).instance;
  }
}

/** Load once; resolves to a synchronous evaluator. */
export function loadGate(): Promise<(command: string) => GateVerdict> {
  loading ??= instantiate().then((instance) => {
    const x = instance.exports as unknown as Exports;
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    return (command: string): GateVerdict => {
      const input = enc.encode(command);
      const ptr = x.alloc(input.length);
      new Uint8Array(x.memory.buffer, ptr, input.length).set(input);
      const packed = x.evaluate(ptr, input.length);
      x.dealloc(ptr, input.length);
      const outPtr = Number(packed >> 32n);
      const outLen = Number(packed & 0xffffffffn);
      const json = dec.decode(new Uint8Array(x.memory.buffer, outPtr, outLen).slice());
      x.dealloc(outPtr, outLen);
      return JSON.parse(json) as GateVerdict;
    };
  });
  return loading;
}

export async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}
