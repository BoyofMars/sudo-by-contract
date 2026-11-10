// Request signing for the private relay. Shared by the SDK (signing) and the
// relay (verification); the Rust gate and the console implement the same
// scheme byte-for-byte:
//
//   Authorization: SBC-Ed25519 pk=<ed25519:base58>,ts=<unix ms>,sig=<base64>
//   sig = Ed25519( utf8("sbc-relay/v1\n" + METHOD + "\n" + PATH_AND_QUERY + "\n" + ts + "\n" + sha256hex(body)) )
//
// where body is the raw request body bytes, or the empty byte string when the
// request has no body (so GETs sign sha256("") = e3b0c442...).

import {
  b64decode,
  b64encode,
  hexEncode,
  publicKeyFromString,
  publicKeyToString,
  sha256,
  utf8,
  verify,
  type Signer,
} from "../../sbc-client/src/index.ts";

export const RELAY_AUTH_SCHEME = "SBC-Ed25519";
export const RELAY_AUTH_DOMAIN = "sbc-relay/v1";
const EMPTY = new Uint8Array();

export async function relayAuthMessage(method: string, pathAndQuery: string, ts: number, body: Uint8Array = EMPTY): Promise<Uint8Array> {
  const bodyHash = hexEncode(await sha256(body));
  return utf8.encode(`${RELAY_AUTH_DOMAIN}\n${method.toUpperCase()}\n${pathAndQuery}\n${ts}\n${bodyHash}`);
}

/** Produce the Authorization header value for one request. */
export async function signRelayRequest(
  signer: Signer,
  method: string,
  pathAndQuery: string,
  body: Uint8Array = EMPTY,
  ts: number = Date.now(),
): Promise<string> {
  const msg = await relayAuthMessage(method, pathAndQuery, ts, body);
  const sig = await signer.sign(msg);
  return `${RELAY_AUTH_SCHEME} pk=${publicKeyToString(signer.publicKey)},ts=${ts},sig=${b64encode(sig)}`;
}

export interface ParsedAuth {
  pk: string;
  ts: number;
  sig: Uint8Array;
  sigB64: string;
}

export function parseRelayAuth(header: string | undefined | null): ParsedAuth | null {
  if (!header) return null;
  const h = header.trim();
  if (!h.startsWith(RELAY_AUTH_SCHEME + " ")) return null;
  const fields: Record<string, string> = {};
  for (const part of h.slice(RELAY_AUTH_SCHEME.length + 1).split(",")) {
    const i = part.indexOf("=");
    if (i <= 0) return null;
    fields[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  if (!fields.pk || !fields.ts || !fields.sig || !/^\d{1,16}$/.test(fields.ts)) return null;
  try {
    publicKeyFromString(fields.pk);
    const sig = b64decode(fields.sig);
    if (sig.length !== 64) return null;
    return { pk: fields.pk, ts: Number(fields.ts), sig, sigB64: fields.sig };
  } catch {
    return null;
  }
}

/** Verify signature only (freshness, replay and role are the caller's job). */
export async function verifyRelaySignature(a: ParsedAuth, method: string, pathAndQuery: string, body: Uint8Array = EMPTY): Promise<boolean> {
  const msg = await relayAuthMessage(method, pathAndQuery, a.ts, body);
  try {
    return await verify(publicKeyFromString(a.pk), msg, a.sig);
  } catch {
    return false;
  }
}
