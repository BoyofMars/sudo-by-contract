import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createTransaction, actionCreators, encodeTransaction as refEncode } from "@near-js/transactions";
import { PublicKey as RefPublicKey } from "@near-js/crypto";
import {
  base58Decode,
  base58Encode,
  encodeTransaction,
  generateKeyMaterial,
  opensshPrivateKey,
  parseCertificateLine,
  publicKeyFromString,
  publicKeyToString,
  secretKeyFromString,
  secretKeyToString,
  signerFromSecretString,
  sshPublicKeyLine,
  utf8,
  verify,
  describePolicy,
  formatDuration,
  NearRpc,
} from "../src/index.ts";

test("base58 roundtrip and known vector", () => {
  assert.equal(base58Encode(utf8.encode("hello world")), "StV1DL6CwTryKyV");
  assert.deepEqual(base58Decode("StV1DL6CwTryKyV"), utf8.encode("hello world"));
  const z = new Uint8Array([0, 0, 1, 2, 255]);
  assert.deepEqual(base58Decode(base58Encode(z)), z);
});

test("borsh transaction encoding matches @near-js/transactions byte-for-byte", async () => {
  const k = await generateKeyMaterial();
  const blockHash = crypto.getRandomValues(new Uint8Array(32));
  const args = utf8.encode(JSON.stringify({ request_id: 42, action: "service.restart:checkout-api" }));
  const ours = encodeTransaction({
    signerId: "sbc.bagyard.testnet",
    publicKey: k.publicKey,
    nonce: 123456789012n,
    receiverId: "sbc.bagyard.testnet",
    blockHash,
    actions: [{ methodName: "consume", args, gas: 30_000_000_000_000n, deposit: 1n }],
  });
  const ref = refEncode(
    createTransaction(
      "sbc.bagyard.testnet",
      RefPublicKey.fromString(publicKeyToString(k.publicKey)),
      "sbc.bagyard.testnet",
      123456789012n,
      [actionCreators.functionCall("consume", args, 30_000_000_000_000n, 1n)],
      blockHash,
    ),
  );
  assert.deepEqual(ours, new Uint8Array(ref));
});

test("NEAR CLI secret key format roundtrips and signs", async () => {
  const k = await generateKeyMaterial();
  const s = secretKeyToString(k);
  assert.deepEqual(secretKeyFromString(s).seed, k.seed);
  const signer = await signerFromSecretString("x.testnet", s);
  assert.deepEqual(signer.publicKey, k.publicKey);
  const msg = utf8.encode("sudo by contract");
  assert.ok(await verify(k.publicKey, msg, await signer.sign(msg)));
  assert.deepEqual(publicKeyFromString(publicKeyToString(k.publicKey)), k.publicKey);
});

function haveSshKeygen(): boolean {
  try {
    execFileSync("ssh-keygen", ["-?"], { stdio: "ignore" });
    return true;
  } catch (e: any) {
    return e.code !== "ENOENT";
  }
}

/** OpenSSH refuses private keys other users can read; on Windows that is an ACL. */
function restrictToOwner(file: string) {
  if (process.platform === "win32") {
    execFileSync("icacls", [file, "/inheritance:r", "/grant:r", `${process.env.USERNAME}:F`], { stdio: "ignore" });
  }
}

test("openssh private key is accepted by ssh-keygen", { skip: !haveSshKeygen() }, async () => {
  const k = await generateKeyMaterial();
  const dir = mkdtempSync(join(tmpdir(), "sbc-"));
  const file = join(dir, "id_ed25519");
  writeFileSync(file, opensshPrivateKey(k, "sbc-test"), { mode: 0o600 });
  restrictToOwner(file);
  const pub = execFileSync("ssh-keygen", ["-y", "-f", file], { encoding: "utf8" }).trim();
  assert.equal(pub.split(" ").slice(0, 2).join(" "), sshPublicKeyLine(k.publicKey));
});

test("certificate parser reads certificates signed by ssh-keygen", { skip: !haveSshKeygen() }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sbc-"));
  const q = (args: string[]) => execFileSync("ssh-keygen", args, { stdio: "ignore" });
  q(["-q", "-t", "ed25519", "-N", "", "-C", "ca", "-f", join(dir, "ca")]);
  q(["-q", "-t", "ed25519", "-N", "", "-C", "agent", "-f", join(dir, "agent")]);
  q(["-q", "-s", join(dir, "ca"), "-I", "sbc cap=7 agent=deploy-agent res=prod-web-02", "-n", "sbc-prod-web-02",
     "-V", "-1m:+10m", "-z", "7", "-O", "clear", "-O", "force-command=/usr/local/sbin/sbc-gate", join(dir, "agent.pub")]);
  const line = readFileSync(join(dir, "agent-cert.pub"), "utf8");
  const c = parseCertificateLine(line);
  assert.equal(c.serial, 7n);
  assert.deepEqual(c.principals, ["sbc-prod-web-02"]);
  assert.equal(c.keyId, "sbc cap=7 agent=deploy-agent res=prod-web-02");
  assert.equal(c.criticalOptions["force-command"], "/usr/local/sbin/sbc-gate");
  assert.deepEqual(c.extensions, []);
  assert.equal(c.validBefore - c.validAfter, 660);
  assert.equal(sshPublicKeyLine(c.caPublicKey), readFileSync(join(dir, "ca.pub"), "utf8").split(" ").slice(0, 2).join(" "));
});

test("policy sentences read like intent", () => {
  assert.equal(formatDuration(600), "10m");
  assert.equal(
    describePolicy({
      id: "p",
      name: "p",
      description: "",
      effect: "Allow",
      subjects: { all_agents: false, agents: ["deploy-agent"] },
      resources: { ids: [], environments: ["production"], tags: [] },
      actions: [{ kind: "service.restart", targets: ["checkout-api"] }],
      max_duration_secs: 600,
      max_uses: 1,
      approval: { required: 1, approvers: [] },
      conditions: { utc_hours: null, require_source_address: false },
    }),
    "deploy-agent may restart checkout-api once on production servers after one human approval. Access expires after 10m.",
  );
});

test("live testnet MPC signer exposes an Ed25519 domain", { skip: !process.env.SBC_NETWORK_TESTS }, async () => {
  const rpc = new NearRpc();
  const pk = await rpc.view<string>("v1.signer-prod.testnet", "derived_public_key", {
    path: "sbc/ssh-user-ca/v1/production",
    predecessor: "sbc.example.testnet",
    domain_id: 1,
  });
  assert.match(pk, /^ed25519:/);
});
