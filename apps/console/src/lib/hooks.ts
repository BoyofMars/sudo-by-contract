import { useCallback, useEffect, useState } from "react";
import { useData, useQuery } from "./data/context.tsx";
import { friendlyError } from "./data/source.ts";
import { useToast } from "../components/toast.tsx";

/** Display labels for agent/approver/resource ids. Ids stay visible elsewhere. */
export function useLabels() {
  const agents = useQuery((s) => s.agents(), [], { interval: 30_000 });
  const approvers = useQuery((s) => s.approvers(), [], { interval: 60_000 });
  const map = new Map<string, string>();
  agents.data?.forEach((a) => map.set(a.id, a.label));
  approvers.data?.forEach((a) => map.set(a.id, a.label));
  return useCallback((id: string) => map.get(id) ?? id, [agents.data, approvers.data]); // eslint-disable-line react-hooks/exhaustive-deps
}

export function useIdentity() {
  return useData().identity;
}

export function useCanApprove() {
  const id = useIdentity();
  return !!id?.binding && (id.binding.role === "Approver" || id.binding.role === "Admin");
}

export function useIsAdmin() {
  return useIdentity()?.binding?.role === "Admin";
}

/** Run a write with toasts and a global refetch. */
export function useAction() {
  const { bump } = useData();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, ok?: string): Promise<{ ok: true; value: T } | { ok: false; error: string }> => {
      setBusy(true);
      setError(null);
      try {
        const v = await fn();
        if (ok) toast(ok, "success");
        bump();
        return { ok: true, value: v };
      } catch (e) {
        const m = friendlyError(e);
        setError(m);
        toast(m, "danger");
        return { ok: false, error: m };
      } finally {
        setBusy(false);
      }
    },
    [bump, toast],
  );
  return { run, busy, error, setError };
}

export type ThemePref = "system" | "light" | "dark";

/**
 * [stored preference, setter, the theme actually shown]. Toggles should flip
 * the theme actually shown: with the preference at "system" on a dark OS,
 * setting "dark" would change nothing on screen.
 */
export function useTheme(): [ThemePref, (t: ThemePref) => void, "light" | "dark"] {
  const systemDark = useMediaQuery("(prefers-color-scheme: dark)");
  const [pref, setPref] = useState<ThemePref>(() => {
    try {
      const t = localStorage.getItem("sbc.theme");
      return t === "light" || t === "dark" ? t : "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    const el = document.documentElement;
    if (pref === "system") el.removeAttribute("data-theme");
    else el.setAttribute("data-theme", pref);
    try {
      if (pref === "system") localStorage.removeItem("sbc.theme");
      else localStorage.setItem("sbc.theme", pref);
    } catch {
      /* ignore */
    }
  }, [pref]);
  return [pref, setPref, pref === "system" ? (systemDark ? "dark" : "light") : pref];
}

export function useMediaQuery(q: string) {
  const [m, setM] = useState(() => window.matchMedia(q).matches);
  useEffect(() => {
    const mq = window.matchMedia(q);
    const on = () => setM(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [q]);
  return m;
}
