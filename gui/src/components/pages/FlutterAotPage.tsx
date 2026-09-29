import { useEffect, useMemo, useSyncExternalStore } from "react";
import { Link, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { Binary } from "lucide-react";
import { SiFlutter, SiReact } from "@icons-pack/react-simple-icons";

import { DecompilerShell, type FileStore } from "@/components/shared/DecompilerShell";
import { FlutterAotTabPanel } from "@/components/shared/FlutterAotTabPanel";
import { filestore, onStatus, type R2State } from "@/lib/r2";

let snap: R2State = { status: "idle" };
onStatus((state) => { snap = state; });

function useStatus() {
  return useSyncExternalStore(
    (callback) => onStatus(() => callback()),
    () => snap,
  );
}

function Status() {
  const state = useStatus();
  if (state.status === "downloading") return <span>R2: Downloading{state.progress ? ` ${state.progress}%` : "..."}</span>;
  if (state.status === "cached") return <span>R2: Cached</span>;
  if (state.status === "compiling") return <span>R2: Compiling...</span>;
  if (state.status === "failed") return <span>R2: Failed</span>;
  if (state.status === "ready") return <span>R2: Ready</span>;
  return null;
}

const store: FileStore = {
  list: filestore.list,
  put: (file) => filestore.put(file),
  remove: filestore.remove,
  usage: filestore.usage,
  get: filestore.get,
};

export function FlutterAotPage() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();

  useEffect(() => {
    if (searchParams.get("source") !== "module") return;
    const device = searchParams.get("device");
    const pid = searchParams.get("pid");
    const path = searchParams.get("path");
    const name = searchParams.get("name") ?? "libapp.so";
    if (!device || !pid || !path) return;
    setSearchParams({}, { replace: true });

    const fileId = `module-${device}-${pid}-${path}`;
    (async () => {
      if (!await filestore.get(fileId)) {
        const url = `/api/download/${device}/${pid}?path=${encodeURIComponent(path)}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error("Failed to download Flutter AOT binary");
        await filestore.put({
          id: fileId,
          name,
          data: await response.arrayBuffer(),
          addedAt: Date.now(),
          source: "remote",
        });
      }
      const saved = localStorage.getItem("flutter-aot-tabs");
      const state = saved ? JSON.parse(saved) as { tabs: Array<{ id: string; name: string }>; active: string | null } : { tabs: [], active: null };
      if (!state.tabs.some((tab) => tab.id === fileId)) state.tabs.push({ id: fileId, name });
      state.active = fileId;
      localStorage.setItem("flutter-aot-tabs", JSON.stringify(state));
      window.location.reload();
    })().catch((error: unknown) => {
      console.error("Failed to open Flutter module", error);
    });
  }, [searchParams, setSearchParams]);

  const sidebar = useMemo(() => (
    <>
      <Link to="/decompiler/hermes" className="flex items-center justify-center p-2 transition-colors hover:bg-sidebar-accent"><SiReact className="h-5 w-5" /></Link>
      <div className="flex items-center justify-center border-l-2 border-primary bg-sidebar-accent p-2"><SiFlutter className="h-5 w-5" /></div>
      <Link to="/decompiler/radare2" className="flex items-center justify-center p-2 transition-colors hover:bg-sidebar-accent"><Binary className="h-5 w-5" /></Link>
    </>
  ), []);

  return (
    <DecompilerShell
      sidebarItems={sidebar}
      store={store}
      storeKey="flutter-aot-tabs"
      accept=".so,.dylib,.elf,.bin"
      dropLabel={t("flutter_drop_file")}
      dropTypes={t("flutter_file_types")}
      statusLeft={<Status />}
    >
      {(fileId) => <FlutterAotTabPanel key={fileId} fileId={fileId} />}
    </DecompilerShell>
  );
}
