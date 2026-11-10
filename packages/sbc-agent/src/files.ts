// Secret files. OpenSSH refuses private keys other users can read, and so
// should we: 0600 on POSIX, an owner-only ACL on Windows.

import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";

export function restrictToOwner(path: string): void {
  if (process.platform === "win32") {
    const user = process.env.USERNAME;
    if (!user) return;
    try {
      execFileSync("icacls", [path, "/inheritance:r", "/grant:r", `${user}:F`], { stdio: "ignore" });
    } catch {
      /* best effort: ssh will complain loudly if this did not work */
    }
  } else {
    chmodSync(path, 0o600);
  }
}

export function writePrivateFile(path: string, content: string): void {
  writeFileSync(path, content, { mode: 0o600 });
  restrictToOwner(path);
}

export function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
}
