// Relay request authentication: signature, freshness, replay, and the
// on-chain identity of the signing key. Fails closed when the chain cannot be
// consulted.

import { parseRelayAuth, verifyRelaySignature } from "../../../packages/sbc-agent/src/relay-auth.ts";
import type { KeyBinding, Role } from "../../../packages/sbc-client/src/index.ts";

export type BindingResolver = (publicKey: string) => Promise<KeyBinding | null>;

export class AuthError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

export interface Authenticated {
  publicKey: string;
  binding: KeyBinding;
}

export interface AuthOptions {
  now?: () => number;
  maxSkewMs?: number;
  replayWindowMs?: number;
  cacheMs?: number;
}

export class RelayAuthenticator {
  private resolver: BindingResolver;
  private now: () => number;
  private maxSkewMs: number;
  private replayWindowMs: number;
  private cacheMs: number;
  private seen = new Map<string, number>();
  private cache = new Map<string, { at: number; binding: KeyBinding | null }>();

  constructor(resolver: BindingResolver, o: AuthOptions = {}) {
    this.resolver = resolver;
    this.now = o.now ?? Date.now;
    this.maxSkewMs = o.maxSkewMs ?? 120_000;
    this.replayWindowMs = o.replayWindowMs ?? 300_000;
    this.cacheMs = o.cacheMs ?? 60_000;
  }

  private async binding(pk: string): Promise<KeyBinding | null> {
    const t = this.now();
    const c = this.cache.get(pk);
    if (c && t - c.at < this.cacheMs) return c.binding;
    let b: KeyBinding | null;
    try {
      b = await this.resolver(pk);
    } catch {
      throw new AuthError(503, "cannot verify identity: policy contract unreachable");
    }
    this.cache.set(pk, { at: t, binding: b });
    return b;
  }

  private pruneReplay(t: number) {
    if (this.seen.size < 1024) return;
    for (const [k, exp] of this.seen) if (exp < t) this.seen.delete(k);
  }

  /**
   * Authenticate a request. `pathAndQuery` must be exactly what the client
   * signed (for SSE, the bare path, since the signature travels in the query).
   */
  async verify(header: string | undefined | null, method: string, pathAndQuery: string, body: Uint8Array | undefined, roles: Role[]): Promise<Authenticated> {
    const a = parseRelayAuth(header);
    if (!a) throw new AuthError(401, "missing or malformed SBC-Ed25519 authorization");
    const t = this.now();
    if (Math.abs(t - a.ts) > this.maxSkewMs) throw new AuthError(401, "stale or future-dated signature");
    const replayKey = `${a.pk}|${a.ts}|${a.sigB64}`;
    const seenUntil = this.seen.get(replayKey);
    if (seenUntil !== undefined && seenUntil > t) throw new AuthError(401, "replayed signature");
    if (!(await verifyRelaySignature(a, method, pathAndQuery, body))) throw new AuthError(401, "bad signature");
    this.pruneReplay(t);
    this.seen.set(replayKey, t + this.replayWindowMs);
    const b = await this.binding(a.pk);
    if (!b) throw new AuthError(403, "key is not bound to any Sudo by Contract identity");
    if (!roles.includes(b.role)) throw new AuthError(403, `role ${b.role} may not call this endpoint`);
    return { publicKey: a.pk, binding: b };
  }
}
