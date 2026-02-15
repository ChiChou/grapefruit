import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { toast } from "sonner";
import { useMutation } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Platform, Status, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { useRpcMutation, useDroidRpcMutation } from "@/lib/queries";
import { DirectoryTree } from "./DirectoryTree";
import { FileTable } from "./FileTable";
import type { FinderTabParams, UploadFile } from "../../lib/file-explorer.ts";

export type { FinderTabParams };

const PREFIXES = {
  home: "~",
  bundle: "!",
} as const;

export function FinderTab({ params }: IDockviewPanelProps<FinderTabParams>) {
  const { fruity, droid, status, pid, device, platform } = useSession();
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();
  const isDroid = platform === Platform.Droid;

  const initialPath = params?.path || PREFIXES.home;
  const initialTab = initialPath === PREFIXES.bundle ? "bundle" : "home";

  const [activeTab, setActiveTab] = useState<keyof typeof PREFIXES>(initialTab);
  const [items, setItems] = useState<
    import("@agent/fruity/modules/fs").MetaData[]
  >([]);
  const [isLoading, setIsLoading] = useState(false);

  const [fullCwd, setFullCwd] = useState<string | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploadFiles, setUploadFiles] = useState<UploadFile[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const fsApi = isDroid ? droid : fruity;
  const apiReady = status === Status.Ready && !!fsApi;

  const loadDirectory = useCallback(
    async (
      path: string,
    ): Promise<import("@agent/fruity/modules/fs").DirectoryListing> => {
      if (!fsApi) return { cwd: "", list: [] };
      return fsApi.fs.ls(path);
    },
    [fsApi],
  );

  const fruityRenameMutation = useRpcMutation<
    boolean,
    { src: string; dst: string }
  >((api, { src, dst }) => api.fs.mv(src, dst));

  const fruityDeleteMutation = useRpcMutation<boolean, { path: string }>(
    (api, { path }) => api.fs.rm(path),
  );

  const droidRenameMutation = useDroidRpcMutation<
    boolean,
    { src: string; dst: string }
  >((api, { src, dst }) => api.fs.mv(src, dst));

  const droidDeleteMutation = useDroidRpcMutation<boolean, { path: string }>(
    (api, { path }) => api.fs.rm(path),
  );

  const renameMutation = isDroid ? droidRenameMutation : fruityRenameMutation;
  const deleteMutation = isDroid ? droidDeleteMutation : fruityDeleteMutation;

  const handleDirectorySelect = useCallback(
    (path: string) => {
      setIsLoading(true);
      loadDirectory(path)
        .then(({ cwd, list }) => {
          const data = list.filter((e) => !e.dir);
          data.sort((a, b) => a.name.localeCompare(b.name));
          setFullCwd(cwd);
          setItems(data);
        })
        .catch(() => {
          setItems([]);
        })
        .finally(() => setIsLoading(false));
    },
    [loadDirectory],
  );

  const handleDownload = useCallback(
    (fileName: string) => {
      if (pid === undefined || fullCwd === null) return;

      const url = new URL(window.location.href);
      url.pathname = `/api/download/${device}/${pid}`;
      url.searchParams.set("path", `${fullCwd}/${fileName}`);
      window.open(url.toString());
    },
    [pid, device, fullCwd],
  );

  const handlePreview = useCallback(
    (fileName: string, type: string) => {
      const fullPath = `${fullCwd}/${fileName}`;
      const panelId = `preview-${fileName}`;

      const componentMap: Record<string, string> = {
        hex: "hexPreview",
        text: "textEditor",
        sqlite: "sqliteEditor",
        image: "imagePreview",
        plist: "plistPreview",
        font: "fontPreview",
      };

      const component = componentMap[type];
      if (!component) return;

      openSingletonPanel({
        id: panelId,
        component,
        title: fileName,
        params: { path: fullPath },
      });
    },
    [fullCwd, openSingletonPanel],
  );

  const handleRename = useCallback(
    async (oldName: string, newName: string) => {
      if (!fullCwd) return;

      const src = `${fullCwd}/${oldName}`;
      const dst = `${fullCwd}/${newName}`;

      await renameMutation.mutateAsync({ src, dst });
      toast.success(t("file_renamed"));
      // Refresh directory listing
      handleDirectorySelect(fullCwd);
    },
    [fullCwd, renameMutation, t, handleDirectorySelect],
  );

  const handleDelete = useCallback(
    async (fileName: string) => {
      if (!fullCwd) return;

      const path = `${fullCwd}/${fileName}`;

      await deleteMutation.mutateAsync({ path });
      toast.success(t("file_deleted"));
      // Refresh directory listing
      handleDirectorySelect(fullCwd);
    },
    [fullCwd, deleteMutation, t, handleDirectorySelect],
  );

  const uploadFileMutation = useMutation({
    mutationFn: async ({
      file,
      targetPath,
    }: {
      file: File;
      targetPath: string;
    }) => {
      const formData = new FormData();
      formData.append("path", targetPath);
      formData.append("file", file);

      const url = new URL(window.location.href);
      url.pathname = `/api/upload/${device}/${pid}`;
      const response = await fetch(url.toString(), {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }
    },
  });

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      if (activeTab !== "home" || !pid || !device || !fullCwd) return;

      const files = Array.from(e.dataTransfer.files);
      if (files.length === 0) return;

      const newFiles: UploadFile[] = files.map((f) => ({
        name: f.name,
        progress: 0,
      }));
      setUploadFiles(newFiles);
      setUploadOpen(true);

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const targetPath = `${fullCwd}/${file.name}`;

        try {
          await uploadFileMutation.mutateAsync({ file, targetPath });
          setUploadFiles((prev) =>
            prev.map((f, idx) => (idx === i ? { ...f, progress: 100 } : f)),
          );
        } catch (err) {
          setUploadFiles((prev) =>
            prev.map((f, idx) =>
              idx === i
                ? { ...f, progress: 0, error: (err as Error).message }
                : f,
            ),
          );
        }
      }

      setTimeout(() => {
        setUploadOpen(false);
        handleDirectorySelect(fullCwd);
      }, 500);
    },
    [
      activeTab,
      pid,
      device,
      fullCwd,
      handleDirectorySelect,
      uploadFileMutation,
    ],
  );

  useEffect(() => {
    if (!apiReady) return;
    const path = PREFIXES[activeTab];
    handleDirectorySelect(path);
  }, [apiReady, activeTab, handleDirectorySelect]);

  useEffect(() => {
    if (!apiReady || !params?.path) return;
    if (params.path === "!") {
      setActiveTab("bundle");
    } else {
      setActiveTab("home");
    }
  }, [apiReady, params?.path]);

  return (
    <>
      <ResizablePanelGroup direction="horizontal" autoSaveId="finder-split">
        <ResizablePanel defaultSize={15} minSize={5} maxSize={80}>
          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as "bundle" | "home")}
            className="h-full flex flex-col"
          >
            <TabsList variant="line" className="w-full">
              <TabsTrigger value="home" className="flex-1">
                {t("home")}
              </TabsTrigger>
              <TabsTrigger value="bundle" className="flex-1">
                {isDroid ? t("apk") : t("bundle")}
              </TabsTrigger>
            </TabsList>
            <TabsContent value="bundle" className="flex-1 overflow-hidden mt-0">
              <DirectoryTree
                root="!"
                apiReady={apiReady}
                loadDirectory={loadDirectory}
                onDirectorySelect={handleDirectorySelect}
              />
            </TabsContent>
            <TabsContent value="home" className="flex-1 overflow-hidden mt-0">
              <DirectoryTree
                root="~"
                apiReady={apiReady}
                loadDirectory={loadDirectory}
                onDirectorySelect={handleDirectorySelect}
              />
            </TabsContent>
          </Tabs>
        </ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel defaultSize={85}>
          <div
            className="h-full relative"
            onDragOver={(e) => {
              e.preventDefault();
              if (activeTab === "home") setIsDragOver(true);
            }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
          >
            {isDragOver && (
              <div className="absolute inset-0 bg-primary/10 flex items-center justify-center z-10 border-2 border-dashed border-primary">
                <span className="text-primary font-medium">
                  {t("drop_files_here")}
                </span>
              </div>
            )}
            <FileTable
              items={items}
              isLoading={isLoading}
              cwd={fullCwd!}
              onDownload={handleDownload}
              onPreview={handlePreview}
              onRename={handleRename}
              onDelete={handleDelete}
            />
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
      <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("uploading")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 max-h-80 overflow-auto">
            {uploadFiles.map((file) => (
              <div key={file.name} className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="truncate max-w-[200px]">{file.name}</span>
                  {file.error ? (
                    <span className="text-destructive text-xs">
                      {file.error}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      {file.progress === 100
                        ? t("completed")
                        : `${file.progress}%`}
                    </span>
                  )}
                </div>
                <Progress value={file.progress} />
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
