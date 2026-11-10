// Device keys: non-extractable WebCrypto Ed25519 key pairs persisted as
// CryptoKey objects in IndexedDB (structured clone keeps them non-extractable).
// Page script can ask the key to sign; nothing can read the private key out.
// One device key per contract.

const DB = "sbc-console";
const STORE = "device-keys";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  return new Promise<T>((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const r = fn(t.objectStore(STORE));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  }).finally(() => db.close());
}

export async function loadDeviceKey(contractId: string): Promise<CryptoKeyPair | null> {
  try {
    const v = await tx<CryptoKeyPair | undefined>("readonly", (s) => s.get(contractId) as IDBRequest<CryptoKeyPair | undefined>);
    return v ?? null;
  } catch {
    return null;
  }
}

export async function saveDeviceKey(contractId: string, kp: CryptoKeyPair): Promise<void> {
  await tx("readwrite", (s) => s.put(kp, contractId));
}

export async function deleteDeviceKey(contractId: string): Promise<void> {
  await tx("readwrite", (s) => s.delete(contractId));
}

export function supportsEd25519(): Promise<boolean> {
  return crypto.subtle
    .generateKey({ name: "Ed25519" }, false, ["sign", "verify"])
    .then(() => true)
    .catch(() => false);
}
