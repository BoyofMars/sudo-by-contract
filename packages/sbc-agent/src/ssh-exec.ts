// Running the approved action over SSH with the stock OpenSSH client.
//
// The command is passed to ssh as one argv element and never through a local
// shell. On the server, sshd forces every session through sbc-gate, which
// parses that text into a typed action or refuses it.

import { spawn } from "node:child_process";

export interface SshTarget {
  user: string;
  host: string;
  port: number;
}

/** Parse `user@host:port`, `host:port`, `user@host` or `host`. */
export function parseSshTarget(s: string, defaults: { user?: string; port?: number } = {}): SshTarget {
  const m = /^(?:([A-Za-z0-9._-]+)@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)(?::(\d{1,5}))?$/.exec(s.trim());
  if (!m) throw new Error(`invalid SSH target "${s}" (expected user@host:port)`);
  const host = m[2].replace(/^\[|\]$/g, "");
  if (host.startsWith("-")) throw new Error("host may not start with '-'");
  const port = m[3] ? Number(m[3]) : defaults.port ?? 22;
  if (port < 1 || port > 65535) throw new Error("invalid port");
  return { user: m[1] ?? defaults.user ?? "sbc-agent", host, port };
}

export interface SshArgvOptions {
  keyPath: string;
  certPath: string;
  knownHostsPath: string;
  target: SshTarget;
  command: string;
  connectTimeoutSecs?: number;
}

export function buildSshArgv(o: SshArgvOptions): string[] {
  if (/[\r\n\0]/.test(o.command)) throw new Error("command may not contain newlines or NUL");
  return [
    "-i", o.keyPath,
    "-o", `CertificateFile=${o.certPath}`,
    "-o", "IdentitiesOnly=yes",
    "-o", "IdentityAgent=none",
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", `UserKnownHostsFile=${o.knownHostsPath}`,
    "-o", `ConnectTimeout=${o.connectTimeoutSecs ?? 10}`,
    "-o", "RequestTTY=no",
    "-p", String(o.target.port),
    "-l", o.target.user,
    "--",
    o.target.host,
    o.command,
  ];
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export function runSsh(
  argv: string[],
  opts: { sshBinary?: string; timeoutMs?: number; onStdout?: (s: string) => void; onStderr?: (s: string) => void } = {},
): Promise<ExecResult> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(opts.sshBinary ?? "ssh", argv, { stdio: ["ignore", "pipe", "pipe"], shell: false });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs ?? 120_000);
    child.stdout.setEncoding("utf8").on("data", (d: string) => {
      stdout += d;
      opts.onStdout?.(d);
    });
    child.stderr.setEncoding("utf8").on("data", (d: string) => {
      stderr += d;
      opts.onStderr?.(d);
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ exitCode: code ?? (signal ? 128 : 1), stdout, stderr, durationMs: Date.now() - started });
    });
  });
}
