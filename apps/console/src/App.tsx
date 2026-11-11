import { useEffect, useMemo } from "react";
import { resolveConfig } from "./lib/config.ts";
import { LiveSource } from "./lib/data/live.ts";
import { PreviewSource } from "./lib/data/preview.ts";
import { DataProvider } from "./lib/data/context.tsx";
import { useRoute } from "./lib/router.tsx";
import { ToastProvider } from "./components/toast.tsx";
import { Landing } from "./pages/Landing.tsx";
import { Join } from "./pages/Join.tsx";
import { Proof } from "./pages/Proof.tsx";
import { Shell } from "./pages/Shell.tsx";

export function App() {
  const route = useRoute();
  // Resolve on every navigation (hash-only navigation does not reload the
  // app), but keep the same source while the effective connection is
  // unchanged, so the simulation keeps its state across pages.
  const cfg = resolveConfig();
  const connKey = cfg.contractId ? `${cfg.contractId}|${cfg.rpcUrl}|${cfg.relayUrl ?? ""}` : "preview";
  const source = useMemo(
    () => (cfg.contractId ? new LiveSource(cfg.contractId, cfg.rpcUrl, cfg.relayUrl) : new PreviewSource()),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [connKey],
  );
  // A new page starts at the top (hash navigation keeps the old scroll position).
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [route.path]);

  let page;
  if (route.path === "/" || route.path === "") page = <Landing />;
  else if (route.path === "/join") page = <Join query={route.query} />;
  else if (route.path === "/proof") page = <Proof query={route.query} />;
  else if (route.path.startsWith("/console")) page = <Shell path={route.path} query={route.query} />;
  else page = <Landing />;

  return (
    <ToastProvider>
      <DataProvider source={source}>{page}</DataProvider>
    </ToastProvider>
  );
}
