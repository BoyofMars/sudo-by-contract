// Ed25519 keys via WebCrypto (browsers and Node >= 22 share this API).
//
// Two kinds of signers:
//  * device keys in the console are generated NON-EXTRACTABLE and persisted
//    as CryptoKey objects in IndexedDB: script on the page can ask them to
//    sign, but nothing can read the private key out;
//  * agents, CLIs and the relay load keys from files in NEAR CLI format
//    (`ed25519:<base58 seed||pub>`).

import { base58Decode, base58Encode, concat } from "./encoding.ts";

const subtle = globalThis.crypto.subtle;
const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export interface Signer {
  /** NEAR account that owns the access key (for role keys: the contract account). */
  accountId: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export function publicKeyToString(pk: Uint8Array): string {
  return "ed25519:" + base58Encode(pk);
}

export function publicKeyFromString(s: string): Uint8Array {
  const [curve, data] = s.split(":");
  if (curve !== "ed25519" || !data) throw new Error("expected an ed25519:<base58> public key");
  const pk = base58Decode(data);
  if (pk.length !== 32) throw new Error("ed25519 public keys are 32 bytes");
  return pk;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", data as BufferSource));
}

export async function importSeed(seed: Uint8Array, extractable = false): Promise<CryptoKey> {
  if (seed.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return subtle.importKey("pkcs8", concat(PKCS8_ED25519_PREFIX, seed) as BufferSource, { name: "Ed25519" }, extractable, ["sign"]);
}

async function rawPublic(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

async function signWith(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign({ name: "Ed25519" }, key, message as BufferSource));
}

export async function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const k = await subtle.importKey("raw", publicKey as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  return subtle.verify({ name: "Ed25519" }, k, signature as BufferSource, message as BufferSource);
}

export interface KeyMaterial {
  seed: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate a key whose seed the caller keeps (files, ephemeral SSH keys). */
export async function generateKeyMaterial(): Promise<KeyMaterial> {
  const kp = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
  return { seed: pkcs8.slice(pkcs8.length - 32), publicKey: await rawPublic(kp.publicKey) };
}

/** NEAR CLI secret format: `ed25519:` + base58(seed || public key). */
export function secretKeyToString(k: KeyMaterial): string {
  return "ed25519:" + base58Encode(concat(k.seed, k.publicKey));
}

export function secretKeyFromString(s: string): KeyMaterial {
  const [curve, data] = s.split(":");
  if (curve !== "ed25519" || !data) throw new Error("expected ed25519:<base58> secret key");
  const raw = base58Decode(data);
  if (raw.length !== 64 && raw.length !== 32) throw new Error("ed25519 secret keys are 64 (or 32) bytes");
  return { seed: raw.slice(0, 32), publicKey: raw.length === 64 ? raw.slice(32) : new Uint8Array() };
}

export async function signerFromKeyMaterial(accountId: string, k: KeyMaterial): Promise<Signer> {
  const key = await importSeed(k.seed);
  let publicKey = k.publicKey;
  if (publicKey.length !== 32) {
    // derive the public key by round-tripping through an extractable import
    const ext = await importSeed(k.seed, true);
    const jwk = await subtle.exportKey("jwk", ext);
    publicKey = base64UrlDecode(jwk.x!);
  }
  return { accountId, publicKey, sign: (m) => signWith(key, m) };
}

export async function signerFromSecretString(accountId: string, secret: string): Promise<Signer> {
  return signerFromKeyMaterial(accountId, secretKeyFromString(secret));
}

/** A non-extractable device key (browser). Persist the returned CryptoKeyPair in IndexedDB. */
export async function generateDeviceKey(): Promise<CryptoKeyPair> {
  return (await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
}

export async function signerFromCryptoKeyPair(accountId: string, kp: CryptoKeyPair): Promise<Signer> {
  const publicKey = await rawPublic(kp.publicKey);
  return { accountId, publicKey, sign: (m) => signWith(kp.privateKey, m) };
}

function base64UrlDecode(s: string): Uint8Array {
  const b = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
