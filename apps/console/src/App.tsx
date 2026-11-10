import { useMemo } from "react";
import { resolveConfig } from "./lib/config.ts";
import { LiveSource } from "./lib/data/live.ts";
import { PreviewSource } from "./lib/data/preview.ts";
import { DataProvider } from "./lib/data/context.tsx";
import { useRoute } from "./lib/router.tsx";
import { ToastProvider } from "./components/toast.tsx";
import { Landing } from "./pages/Landing.tsx";
import { Join } from "./pages/Join.tsx";
import { Shell } from "./pages/Shell.tsx";

export function App() {
  const route = useRoute();
  // Re-resolve when a link switches contract or preview within an open page
  // (hash-only navigation does not reload the app).
  const urlContract = route.query.get("contract");
  const urlPreview = route.query.get("preview");
  const source = useMemo(() => {
    const cfg = resolveConfig();
    return cfg.contractId ? new LiveSource(cfg.contractId, cfg.rpcUrl, cfg.relayUrl) : new PreviewSource();
  }, [urlContract, urlPreview]);

  let page;
  if (route.path === "/" || route.path === "") page = <Landing />;
  else if (route.path === "/join") page = <Join query={route.query} />;
  else if (route.path.startsWith("/console")) page = <Shell path={route.path} query={route.query} />;
  else page = <Landing />;

  return (
    <ToastProvider>
      <DataProvider source={source}>{page}</DataProvider>
    </ToastProvider>
  );
}
