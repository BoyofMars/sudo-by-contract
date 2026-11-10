import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { DataSource, Identity } from "./source.ts";

interface Ctx {
  source: DataSource;
  version: number;
  /** Force every query to refetch (after a write, or on a relay event). */
  bump: () => void;
  /** chain time − local time, from the last overview */
  clockOffset: number;
  setClockOffset: (ms: number) => void;
  identity: Identity | null;
  reloadIdentity: () => void;
}

const DataCtx = createContext<Ctx | null>(null);

export function DataProvider({ source, children }: { source: DataSource; children: ReactNode }) {
  const [version, setVersion] = useState(0);
  const [clockOffset, setClockOffset] = useState(0);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const bump = useCallback(() => setVersion((v) => v + 1), []);
  const reloadIdentity = useCallback(() => {
    source.identity().then(setIdentity).catch(() => setIdentity({ publicKey: null, binding: null }));
  }, [source]);

  useEffect(() => {
    reloadIdentity();
    const unsub = source.subscribe(() => bump());
    return unsub;
  }, [source, bump, reloadIdentity]);

  const value = useMemo(
    () => ({ source, version, bump, clockOffset, setClockOffset, identity, reloadIdentity }),
    [source, version, bump, clockOffset, identity, reloadIdentity],
  );
  return <DataCtx.Provider value={value}>{children}</DataCtx.Provider>;
}

export function useData(): Ctx {
  const c = useContext(DataCtx);
  if (!c) throw new Error("useData outside DataProvider");
  return c;
}

export interface QueryState<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  reload: () => void;
}

/**
 * Fetch from the data source; refetches when deps change, when anything bumps
 * the global version (writes, relay events), and every `interval` ms.
 */
export function useQuery<T>(fn: (s: DataSource) => Promise<T>, deps: unknown[], opts: { interval?: number } = {}): QueryState<T> {
  const { source, version } = useData();
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const gen = useRef(0);

  useEffect(() => {
    const my = ++gen.current;
    fnRef
      .current(source)
      .then((d) => {
        if (gen.current !== my) return;
        setData(d);
        setError(null);
        setLoading(false);
      })
      .catch((e) => {
        if (gen.current !== my) return;
        setError(e);
        setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, version, tick, ...deps]);

  useEffect(() => {
    if (!opts.interval) return;
    const id = setInterval(() => {
      if (document.visibilityState === "visible") setTick((t) => t + 1);
    }, opts.interval);
    return () => clearInterval(id);
  }, [opts.interval]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading: loading && data === undefined, reload };
}

/** Re-render every `ms`; returns chain-adjusted now. */
export function useNow(ms = 1000): number {
  const { clockOffset } = useData();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now + clockOffset;
}
