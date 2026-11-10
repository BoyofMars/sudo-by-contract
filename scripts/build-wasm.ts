// Build crates/sbc-wasm (sbc-core's gate logic) for the browser playground.
//
//   node scripts/build-wasm.ts
//
// Output: apps/console/src/wasm/sbc_core.wasm (committed, so the console can
// be built without a Rust toolchain). Local paths are remapped so nothing about
// the build machine ends up in the published artifact.

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

const root = resolve(import.meta.dirname, "..");
const cargoHome = process.env.CARGO_HOME ?? join(homedir(), ".cargo");
const rustup = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
const remap = [`${root}=/src`, `${cargoHome}=/cargo`, `${rustup}=/rustup`, `${homedir()}=/home`]
  .map((m) => `--remap-path-prefix=${m}`)
  .join(" ");

execFileSync("cargo", ["build", "-p", "sbc-wasm", "--target", "wasm32-unknown-unknown", "--release"], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, RUSTFLAGS: `${process.env.RUSTFLAGS ?? ""} ${remap}`.trim() },
});

const meta = JSON.parse(execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: root, encoding: "utf8" }));
const built = join(meta.target_directory, "wasm32-unknown-unknown", "release", "sbc_wasm.wasm");
const outDir = join(root, "apps", "console", "src", "wasm");
mkdirSync(outDir, { recursive: true });
const out = join(outDir, "sbc_core.wasm");
copyFileSync(built, out);

const bytes = readFileSync(out);
const leaks = [homedir(), root].filter((p) => bytes.includes(Buffer.from(p)));
if (leaks.length) throw new Error(`local paths leaked into the wasm: ${leaks.join(", ")}`);
console.log(`wrote ${out} (${statSync(out).size} bytes, sha256 ${createHash("sha256").update(bytes).digest("hex").slice(0, 16)}…)`);
