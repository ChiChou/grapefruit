import { useEffect, useMemo, useSyncExternalStore } from "react";
import { useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { SiReact } from "@icons-pack/react-simple-icons";
import { Binary } from "lucide-react";
import { Link } from "react-router";

import { DecompilerShell, type FileStore } from "@/components/shared/DecompilerShell";
import { HermesTabPanel } from "@/components/shared/HermesTabPanel";
import * as store from "@/lib/hermes-store";
import { onStatus, type WasmState } from "@/lib/hbc";

// WASM status subscription
let wasmSnap: WasmState = { status: "idle" };
onStatus((s) => { wasmSnap = s; });

function useWasmStatus(): WasmState {
  return useSyncExternalStore(
    (cb) => onStatus(() => cb()),
    () => wasmSnap,
  );
}

function WasmStatusText() {
  const ws = useWasmStatus();
  if (ws.status === "downloading")
    return <span>WASM: Downloading{ws.progress ? ` ${ws.progress}%` : "..."}</span>;
  if (ws.status === "compiling") return <span>WASM: Compiling...</span>;
  if (ws.status === "failed") return <span>WASM: Failed</span>;
  if (ws.status === "ready") return <span>WASM: Ready</span>;
  return null;
}

// Adapt hermes-store to FileStore interface
const hermesStore: FileStore = {
  list: store.list,
  put: (f) => store.put({ id: f.id, name: f.name, data: f.data, addedAt: f.addedAt, source: f.source as "local" | "remote" }),
  remove: store.remove,
  usage: store.usage,
  get: store.get,
};

export function HermesPage() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();

  // Handle ?source=download from workspace (inject file into store)
  useEffect(() => {
    const source = searchParams.get("source");
    if (source !== "download") return;
    const device = searchParams.get("device");
    const identifier = searchParams.get("identifier");
    const id = searchParams.get("id");
    const name = searchParams.get("name") ?? "hermes";
    if (!device || !identifier || !id) return;

    setSearchParams({}, { replace: true });

    const fileId = `remote-${device}-${identifier}-${id}`;
    (async () => {
      const existing = await store.get(fileId);
      if (existing) return; // already stored, shell will pick it up
      try {
        const res = await fetch(`/api/hermes/${device}/${identifier}/download/${id}`);
        if (!res.ok) return;
        const data = await res.arrayBuffer();
        await store.put({ id: fileId, name, data, addedAt: Date.now(), source: "remote" });
        // Force reload tab state by touching localStorage
        const saved = localStorage.getItem("hermes-tabs");
        if (saved) {
          const state = JSON.parse(saved);
          if (!state.tabs.some((t: any) => t.id === fileId)) {
            state.tabs.push({ id: fileId, name });
            state.active = fileId;
            localStorage.setItem("hermes-tabs", JSON.stringify(state));
          }
        } else {
          localStorage.setItem("hermes-tabs", JSON.stringify({ tabs: [{ id: fileId, name }], active: fileId }));
        }
        window.location.reload();
      } catch { /* ignore */ }
    })();
  }, [searchParams, setSearchParams]);

  const sidebar = useMemo(() => (
    <>
      <div className="p-2 flex items-center justify-center bg-sidebar-accent border-l-2 border-primary">
        <SiReact className="h-5 w-5" />
      </div>
      <Link to="/decompiler/radare2" className="p-2 flex items-center justify-center hover:bg-sidebar-accent transition-colors">
        <Binary className="h-5 w-5" />
      </Link>
    </>
  ), []);

  return (
    <DecompilerShell
      sidebarItems={sidebar}
      store={hermesStore}
      storeKey="hermes-tabs"
      accept=".hbc,.jsbundle"
      dropLabel={t("hermes_drop_file")}
      dropTypes={t("hermes_file_types")}
      statusLeft={<WasmStatusText />}
    >
      {(fileId) => <HermesTabPanel key={fileId} fileId={fileId} />}
    </DecompilerShell>
  );
}
