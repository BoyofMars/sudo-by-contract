// Watches the contract for request state changes. Drives the SSE stream and
// approval notifications. The chain stays the source of truth: this only
// observes it.

import type { AccessRequest, RequestState } from "../../../packages/sbc-client/src/index.ts";

export interface RequestSource {
  recentRequests(): Promise<AccessRequest[]>;
}

export interface RequestChange {
  id: number;
  state: RequestState;
  previous: RequestState | null;
  agent_id: string;
  resource_id: string;
  action: string;
  request: AccessRequest;
}

export class RequestWatcher {
  private source: RequestSource;
  private known = new Map<number, RequestState>();
  private listeners = new Set<(c: RequestChange) => void>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private polling = false;
  seeded = false;
  lastError: string | null = null;

  constructor(source: RequestSource) {
    this.source = source;
  }

  subscribe(fn: (c: RequestChange) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** One poll. Exposed for tests. The first poll emits every request it sees. */
  async poll(): Promise<RequestChange[]> {
    if (this.polling) return [];
    this.polling = true;
    try {
      const rs = await this.source.recentRequests();
      this.lastError = null;
      const changes: RequestChange[] = [];
      for (const r of rs) {
        const prev = this.known.get(r.id) ?? null;
        if (prev !== r.state) {
          this.known.set(r.id, r.state);
          changes.push({ id: r.id, state: r.state, previous: prev, agent_id: r.agent_id, resource_id: r.resource_id, action: r.action, request: r });
        }
      }
      this.seeded = true;
      for (const c of changes.sort((a, b) => a.id - b.id)) for (const l of this.listeners) l(c);
      return changes;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      return [];
    } finally {
      this.polling = false;
    }
  }

  start(intervalMs = 2000) {
    if (this.timer) return;
    void this.poll();
    this.timer = setInterval(() => void this.poll(), intervalMs);
    this.timer.unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}
