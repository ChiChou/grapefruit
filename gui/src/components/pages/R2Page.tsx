import { useMemo, useSyncExternalStore } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { Binary } from "lucide-react";
import { SiReact } from "@icons-pack/react-simple-icons";

import { DecompilerShell, type FileStore } from "@/components/shared/DecompilerShell";
import { R2TabPanel } from "@/components/shared/R2TabPanel";
import { filestore, onStatus, type R2State } from "@/lib/r2";

let r2Snap: R2State = { status: "idle" };
onStatus((s) => { r2Snap = s; });

function useR2Status(): R2State {
  return useSyncExternalStore(
    (cb) => onStatus(() => cb()),
    () => r2Snap,
  );
}

function R2StatusText() {
  const ws = useR2Status();
  if (ws.status === "downloading")
    return <span>R2: Downloading{ws.progress ? ` ${ws.progress}%` : "..."}</span>;
  if (ws.status === "cached") return <span>R2: Cached</span>;
  if (ws.status === "compiling") return <span>R2: Compiling...</span>;
  if (ws.status === "failed") return <span>R2: Failed</span>;
  if (ws.status === "ready") return <span>R2: Ready</span>;
  return null;
}

const r2Store: FileStore = {
  list: filestore.list,
  put: (f) => filestore.put({ id: f.id, name: f.name, data: f.data, addedAt: f.addedAt, source: f.source }),
  remove: filestore.remove,
  usage: filestore.usage,
  get: filestore.get,
};

export function R2Page() {
  const { t } = useTranslation();

  const sidebar = useMemo(() => (
    <>
      <Link to="/decompiler/hermes" className="p-2 flex items-center justify-center hover:bg-sidebar-accent transition-colors">
        <SiReact className="h-5 w-5" />
      </Link>
      <div className="p-2 flex items-center justify-center bg-sidebar-accent border-l-2 border-primary">
        <Binary className="h-5 w-5" />
      </div>
    </>
  ), []);

  return (
    <DecompilerShell
      sidebarItems={sidebar}
      store={r2Store}
      storeKey="r2-tabs"
      accept=".dex,.apk,.so,.dylib,.elf,.exe,.bin,.o,.a,.macho"
      dropLabel={t("r2_drop_file")}
      dropTypes={t("r2_file_types")}
      statusLeft={<R2StatusText />}
    >
      {(fileId) => <R2TabPanel key={fileId} fileId={fileId} />}
    </DecompilerShell>
  );
}
