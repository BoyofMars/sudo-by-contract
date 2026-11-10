// Relay storage (node:sqlite). Holds only what must stay off-chain: private
// context documents (content-addressed) and gate execution reports (redacted
// commands). Both are pruned after the retention period.

import { DatabaseSync } from "node:sqlite";
import type { GateReport } from "../../../packages/sbc-agent/src/relay-client.ts";

export interface StoredReport extends GateReport {
  id: number;
  received_at_ms: number;
}

export class RelayStore {
  db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS contexts (
        hash TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        body BLOB NOT NULL,
        created_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS gate_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource_id TEXT NOT NULL,
        request_id INTEGER,
        decision TEXT NOT NULL,
        code TEXT NOT NULL,
        program TEXT NOT NULL,
        redacted_command TEXT NOT NULL,
        command_sha256 TEXT NOT NULL,
        action TEXT,
        session TEXT NOT NULL,
        exit_code INTEGER,
        duration_ms INTEGER,
        at_ms INTEGER NOT NULL,
        received_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS gate_reports_request ON gate_reports(request_id);
      CREATE INDEX IF NOT EXISTS gate_reports_resource ON gate_reports(resource_id);
      CREATE TABLE IF NOT EXISTS notified (
        request_id INTEGER PRIMARY KEY,
        at_ms INTEGER NOT NULL
      );
    `);
  }

  putContext(hash: string, agentId: string, body: Uint8Array, at: number): void {
    this.db.prepare("INSERT OR IGNORE INTO contexts (hash, agent_id, body, created_at_ms) VALUES (?, ?, ?, ?)").run(hash, agentId, body, at);
  }

  getContext(hash: string): { hash: string; agent_id: string; body: Uint8Array; created_at_ms: number } | null {
    const row = this.db.prepare("SELECT hash, agent_id, body, created_at_ms FROM contexts WHERE hash = ?").get(hash) as any;
    if (!row) return null;
    return { hash: row.hash, agent_id: row.agent_id, body: new Uint8Array(row.body), created_at_ms: Number(row.created_at_ms) };
  }

  addReport(r: GateReport, receivedAt: number): number {
    const res = this.db
      .prepare(
        `INSERT INTO gate_reports (resource_id, request_id, decision, code, program, redacted_command, command_sha256, action, session, exit_code, duration_ms, at_ms, received_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(r.resource_id, r.request_id, r.decision, r.code, r.program, r.redacted_command, r.command_sha256, r.action, r.session, r.exit_code, r.duration_ms, r.at_ms, receivedAt);
    return Number(res.lastInsertRowid);
  }

  listReports(q: { request_id?: number; resource_id?: string; limit?: number }): StoredReport[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (q.request_id !== undefined) {
      where.push("request_id = ?");
      args.push(q.request_id);
    }
    if (q.resource_id) {
      where.push("resource_id = ?");
      args.push(q.resource_id);
    }
    const limit = Math.min(Math.max(q.limit ?? 100, 1), 500);
    const sql = `SELECT * FROM gate_reports ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY id DESC LIMIT ${limit}`;
    return (this.db.prepare(sql).all(...args) as any[]).map((row) => ({
      id: Number(row.id),
      resource_id: row.resource_id,
      request_id: row.request_id === null ? null : Number(row.request_id),
      decision: row.decision,
      code: row.code,
      program: row.program,
      redacted_command: row.redacted_command,
      command_sha256: row.command_sha256,
      action: row.action,
      session: row.session,
      exit_code: row.exit_code === null ? null : Number(row.exit_code),
      duration_ms: row.duration_ms === null ? null : Number(row.duration_ms),
      at_ms: Number(row.at_ms),
      received_at_ms: Number(row.received_at_ms),
    }));
  }

  /** Returns true the first time a request id is marked (exactly-once notifications across restarts). */
  markNotified(requestId: number, at: number): boolean {
    const res = this.db.prepare("INSERT OR IGNORE INTO notified (request_id, at_ms) VALUES (?, ?)").run(requestId, at);
    return Number(res.changes) > 0;
  }

  prune(olderThanMs: number): { contexts: number; reports: number } {
    const c = this.db.prepare("DELETE FROM contexts WHERE created_at_ms < ?").run(olderThanMs);
    const r = this.db.prepare("DELETE FROM gate_reports WHERE received_at_ms < ?").run(olderThanMs);
    this.db.prepare("DELETE FROM notified WHERE at_ms < ?").run(olderThanMs);
    return { contexts: Number(c.changes), reports: Number(r.changes) };
  }

  close() {
    this.db.close();
  }
}
