// Connection config. Resolution order:
//   URL (?contract=&rpc=&relay=, in the query string or the hash query)
//   → localStorage → build-time env (VITE_SBC_CONTRACT / VITE_SBC_RPC / VITE_SBC_RELAY).
// No contract configured ⇒ the console runs on simulated preview data.
// `?preview=1` switches to the simulation for the rest of the visit (tab
// session); `?preview=0` or any `?contract=` switches back.

import { DEFAULT_TESTNET_RPC } from "@sbc/client";

export interface ConsoleConfig {
  contractId: string | null;
  rpcUrl: string;
  relayUrl: string | null;
  forcePreview: boolean;
}

const KEY = "sbc.connection";

function readUrlParams(): URLSearchParams {
  const p = new URLSearchParams(window.location.search);
  const h = window.location.hash;
  const qi = h.indexOf("?");
  if (qi >= 0) new URLSearchParams(h.slice(qi + 1)).forEach((v, k) => p.set(k, v));
  return p;
}

function safeGet(): Partial<ConsoleConfig> {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Partial<ConsoleConfig>) : {};
  } catch {
    return {};
  }
}

export function saveConfig(c: Pick<ConsoleConfig, "contractId" | "rpcUrl" | "relayUrl">) {
  try {
    localStorage.setItem(KEY, JSON.stringify(c));
  } catch {
    /* storage unavailable: config lives for this page only */
  }
}

export function clearConfig() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

const PREVIEW_KEY = "sbc.preview";
function previewSticky(on?: boolean): boolean {
  try {
    if (on === true) sessionStorage.setItem(PREVIEW_KEY, "1");
    else if (on === false) sessionStorage.removeItem(PREVIEW_KEY);
    return sessionStorage.getItem(PREVIEW_KEY) === "1";
  } catch {
    return on === true;
  }
}

/** The public deployment the landing page and "back to live" links point at. */
export const LIVE_CONTRACT: string | null =
  ((import.meta.env.VITE_SBC_LIVE_CONTRACT as string | undefined) || (import.meta.env.VITE_SBC_CONTRACT as string | undefined) || "").trim() || null;

export function resolveConfig(): ConsoleConfig {
  const url = readUrlParams();
  const stored = safeGet();
  const env = import.meta.env;
  const fromUrl = url.get("contract");
  const p = url.get("preview");
  const forcePreview = p === "1" ? previewSticky(true) : p === "0" || fromUrl ? previewSticky(false) : previewSticky();
  const contractId = (fromUrl || stored.contractId || (env.VITE_SBC_CONTRACT as string | undefined) || null)?.trim() || null;
  const rpcUrl = url.get("rpc") || stored.rpcUrl || (env.VITE_SBC_RPC as string | undefined) || DEFAULT_TESTNET_RPC;
  const relayUrl = url.get("relay") || stored.relayUrl || (env.VITE_SBC_RELAY as string | undefined) || null;
  if (fromUrl) saveConfig({ contractId, rpcUrl, relayUrl });
  return { contractId: forcePreview ? null : contractId, rpcUrl, relayUrl, forcePreview };
}

export function networkOf(contractId: string | null): "testnet" | "mainnet" | "preview" {
  if (!contractId) return "preview";
  return contractId.endsWith(".near") ? "mainnet" : "testnet";
}

export function explorerBase(network: string): string {
  return network === "mainnet" ? "https://nearblocks.io" : "https://testnet.nearblocks.io";
}
