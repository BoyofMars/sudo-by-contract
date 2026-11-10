// OpenSSH encodings needed on the agent side: the ephemeral key pair the
// agent generates per request (written in `openssh-key-v1` format so the stock
// `ssh` client can use it) and lightweight certificate inspection.

import { b64decode, b64encode, concat, utf8 } from "./encoding.ts";
import type { KeyMaterial } from "./keys.ts";

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}
function sshString(b: Uint8Array | string): Uint8Array {
  const bytes = typeof b === "string" ? utf8.encode(b) : b;
  return concat(u32(bytes.length), bytes);
}

export function ed25519PublicBlob(pk: Uint8Array): Uint8Array {
  return concat(sshString("ssh-ed25519"), sshString(pk));
}

/** `ssh-ed25519 AAAA... comment` */
export function sshPublicKeyLine(pk: Uint8Array, comment = ""): string {
  const line = "ssh-ed25519 " + b64encode(ed25519PublicBlob(pk));
  return comment ? `${line} ${comment}` : line;
}

/** Unencrypted `openssh-key-v1` private key file, as written by `ssh-keygen -N ""`. */
export function opensshPrivateKey(k: KeyMaterial, comment = "sbc-ephemeral"): string {
  const check = crypto.getRandomValues(new Uint8Array(4));
  let priv = concat(
    check,
    check,
    sshString("ssh-ed25519"),
    sshString(k.publicKey),
    sshString(concat(k.seed, k.publicKey)),
    sshString(comment),
  );
  const pad: number[] = [];
  for (let i = 1; (priv.length + pad.length) % 8 !== 0; i++) pad.push(i);
  priv = concat(priv, new Uint8Array(pad));
  const body = concat(
    utf8.encode("openssh-key-v1\0"),
    sshString("none"),
    sshString("none"),
    sshString(new Uint8Array()),
    u32(1),
    sshString(ed25519PublicBlob(k.publicKey)),
    sshString(priv),
  );
  const b64 = b64encode(body).replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

export interface CertSummary {
  serial: bigint;
  keyId: string;
  principals: string[];
  validAfter: number;
  validBefore: number;
  criticalOptions: Record<string, string>;
  extensions: string[];
  caPublicKey: Uint8Array;
  subjectKey: Uint8Array;
}

class Reader {
  private dv: DataView;
  pos = 0;
  b: Uint8Array;
  constructor(b: Uint8Array) {
    this.b = b;
    this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  u32() {
    const v = this.dv.getUint32(this.pos, false);
    this.pos += 4;
    return v;
  }
  u64() {
    const v = this.dv.getBigUint64(this.pos, false);
    this.pos += 8;
    return v;
  }
  bytes() {
    const n = this.u32();
    if (this.pos + n > this.b.length) throw new Error("truncated certificate");
    const s = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return s;
  }
  str() {
    return utf8.decode(this.bytes());
  }
  done() {
    return this.pos >= this.b.length;
  }
}

/** Parse (not verify) a `ssh-ed25519-cert-v01@openssh.com` line. */
export function parseCertificateLine(line: string): CertSummary {
  const [type, b64] = line.trim().split(/\s+/);
  if (type !== "ssh-ed25519-cert-v01@openssh.com") throw new Error(`unsupported certificate type ${type}`);
  const r = new Reader(b64decode(b64));
  r.str();
  r.bytes(); // nonce
  const subjectKey = r.bytes().slice();
  const serial = r.u64();
  r.u32(); // type
  const keyId = r.str();
  const pr = new Reader(r.bytes());
  const principals: string[] = [];
  while (!pr.done()) principals.push(pr.str());
  const validAfter = Number(r.u64());
  const validBefore = Number(r.u64());
  const co = new Reader(r.bytes());
  const criticalOptions: Record<string, string> = {};
  while (!co.done()) {
    const name = co.str();
    const data = co.bytes();
    criticalOptions[name] = data.length ? new Reader(data).str() : "";
  }
  const ex = new Reader(r.bytes());
  const extensions: string[] = [];
  while (!ex.done()) {
    extensions.push(ex.str());
    ex.bytes();
  }
  r.bytes(); // reserved
  const ca = new Reader(r.bytes());
  ca.str();
  const caPublicKey = ca.bytes().slice();
  return { serial, keyId, principals, validAfter, validBefore, criticalOptions, extensions, caPublicKey, subjectKey };
}
