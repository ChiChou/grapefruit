import { useCallback, useEffect, useRef, useState } from "react";
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
import { Mode, Platform, Status, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { useFruityMutation, useDroidMutation } from "@/lib/queries";
import { DirectoryTree } from "./DirectoryTree";
import { FileTable } from "./FileTable";
import type { FinderTabParams, UploadFile } from "@/lib/explorer.ts";

export type { FinderTabParams };

// Recursively read all files from a FileSystemDirectoryEntry
function readAllEntries(
  dirEntry: FileSystemDirectoryEntry,
  basePath: string,
): Promise<{ file: File; relativePath: string }[]> {
  return new Promise((resolve, reject) => {
    const reader = dirEntry.createReader();
    const results: Promise<{ file: File; relativePath: string }[]>[] = [];

    function readBatch() {
      reader.readEntries((entries) => {
        if (entries.length === 0) {
          Promise.all(results)
            .then((arrays) => resolve(arrays.flat()))
            .catch(reject);
          return;
        }
        for (const entry of entries) {
          const entryPath = basePath ? `${basePath}/${entry.name}` : entry.name;
          if (entry.isDirectory) {
            results.push(
              readAllEntries(entry as FileSystemDirectoryEntry, entryPath),
            );
          } else if (entry.isFile) {
            results.push(
              new Promise((res, rej) => {
                (entry as FileSystemFileEntry).file(
                  (file) => res([{ file, relativePath: entryPath }]),
                  rej,
                );
              }),
            );
          }
        }
        readBatch();
      }, reject);
    }
    readBatch();
  });
}

export function FinderTab({ params }: IDockviewPanelProps<FinderTabParams>) {
  const { fruity, droid, status, pid, device, platform, mode, identifier } =
    useSession();
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();
  const isDroid = platform === Platform.Droid;
  const isDaemon = mode === Mode.Daemon;

  const storageKey =
    device && identifier ? `finder-state:${device}:${identifier}` : null;

  const initialPath = params?.path || "~";
  const defaultTab = initialPath === "!" ? "bundle" : "home";

  // Restore saved state from localStorage (scoped to device + app)
  const [savedState] = useState(() => {
    if (!storageKey) return null;
    try {
      return JSON.parse(localStorage.getItem(storageKey) || "{}");
    } catch {
      return null;
    }
  });
  const [activeTab, setActiveTab] = useState<"home" | "bundle">(() => {
    if (savedState?.activeTab === "home" || savedState?.activeTab === "bundle")
      return savedState.activeTab;
    return defaultTab;
  });
  const [initialSavedCwd] = useState<string | null>(
    () => savedState?.fullCwd || null,
  );
  const restoredRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const uploadAbortRef = useRef(false);

  const [items, setItems] = useState<
    import("@agent/fruity/modules/fs").MetaData[]
  >([]);
  const [isLoading, setIsLoading] = useState(false);

  const [fullCwd, setFullCwd] = useState<string | null>(null);
  const [cwdWritable, setCwdWritable] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploadFiles, setUploadFiles] = useState<UploadFile[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const fsApi = isDroid ? droid : fruity;
  const apiReady = status === Status.Ready && !!fsApi;

  const [roots, setRoots] = useState<{
    home: string;
    bundle: string;
  } | null>(null);

  const loadDirectory = useCallback(
    async (
      path: string,
    ): Promise<import("@agent/fruity/modules/fs").DirectoryListing> => {
      if (!fsApi) return { cwd: "", writable: false, list: [] };
      return fsApi.fs.ls(path);
    },
    [fsApi],
  );

  const fruityRenameMutation = useFruityMutation<
    boolean,
    { src: string; dst: string }
  >((api, { src, dst }) => api.fs.mv(src, dst));

  const fruityDeleteMutation = useFruityMutation<boolean, { path: string }>(
    (api, { path }) => api.fs.rm(path),
  );

  const droidRenameMutation = useDroidMutation<
    boolean,
    { src: string; dst: string }
  >((api, { src, dst }) => api.fs.mv(src, dst));

  const droidDeleteMutation = useDroidMutation<boolean, { path: string }>(
    (api, { path }) => api.fs.rm(path),
  );

  const renameMutation = isDroid ? droidRenameMutation : fruityRenameMutation;
  const deleteMutation = isDroid ? droidDeleteMutation : fruityDeleteMutation;

  const handleDirectorySelect = useCallback(
    (path: string) => {
      setIsLoading(true);
      loadDirectory(path)
        .then(({ cwd, writable, list }) => {
          const data = [...list].sort((a, b) => {
            if (a.dir !== b.dir) return a.dir ? -1 : 1;
            return a.name.localeCompare(b.name);
          });
          setFullCwd(cwd);
          setCwdWritable(writable);
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
      location.replace(url.toString());
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

  const uploadFileList = useCallback(
    async (entries: { file: File; targetPath: string }[]) => {
      if (entries.length === 0 || !fullCwd) return;

      const newFiles: UploadFile[] = entries.map((e) => ({
        name: e.targetPath.replace(`${fullCwd}/`, ""),
        progress: 0,
      }));
      setUploadFiles(newFiles);
      setUploadOpen(true);
      uploadAbortRef.current = false;

      for (let i = 0; i < entries.length; i++) {
        if (uploadAbortRef.current) break;
        const { file, targetPath } = entries[i];
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
    [fullCwd, handleDirectorySelect, uploadFileMutation],
  );

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      if (!cwdWritable || !pid || !device || !fullCwd) return;

      // Try webkitGetAsEntry for folder support
      const dataItems = Array.from(e.dataTransfer.items);
      const allEntries: { file: File; targetPath: string }[] = [];
      let usedEntryApi = false;

      for (const item of dataItems) {
        const entry = item.webkitGetAsEntry?.();
        if (entry) {
          usedEntryApi = true;
          if (entry.isDirectory) {
            const dirFiles = await readAllEntries(
              entry as FileSystemDirectoryEntry,
              entry.name,
            );
            for (const { file, relativePath } of dirFiles) {
              allEntries.push({
                file,
                targetPath: `${fullCwd}/${relativePath}`,
              });
            }
          } else if (entry.isFile) {
            const file = await new Promise<File>((resolve, reject) => {
              (entry as FileSystemFileEntry).file(resolve, reject);
            });
            allEntries.push({
              file,
              targetPath: `${fullCwd}/${file.name}`,
            });
          }
        }
      }

      // Fallback to plain files if webkitGetAsEntry not available
      if (!usedEntryApi) {
        const files = Array.from(e.dataTransfer.files);
        for (const file of files) {
          allEntries.push({
            file,
            targetPath: `${fullCwd}/${file.name}`,
          });
        }
      }

      if (allEntries.length === 0) return;
      await uploadFileList(allEntries);
    },
    [cwdWritable, pid, device, fullCwd, uploadFileList],
  );

  const handleBatchDelete = useCallback(
    async (fileNames: string[]) => {
      if (!fullCwd) return;

      for (const fileName of fileNames) {
        const path = `${fullCwd}/${fileName}`;
        await deleteMutation.mutateAsync({ path });
      }
      toast.success(t("file_deleted"));
      handleDirectorySelect(fullCwd);
    },
    [fullCwd, deleteMutation, t, handleDirectorySelect],
  );

  const handleNavigate = useCallback(
    (folderName: string) => {
      if (!fullCwd) return;
      handleDirectorySelect(`${fullCwd}/${folderName}`);
    },
    [fullCwd, handleDirectorySelect],
  );

  const handleUpload = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleFileInputChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (!files || files.length === 0 || !fullCwd) return;

      const entries = Array.from(files).map((file) => ({
        file,
        targetPath: `${fullCwd}/${file.name}`,
      }));
      await uploadFileList(entries);

      // Reset input so the same files can be re-selected
      e.target.value = "";
    },
    [fullCwd, uploadFileList],
  );

  useEffect(() => {
    if (!apiReady) return;
    fsApi.fs.roots().then(setRoots);
  }, [apiReady, fsApi]);

  useEffect(() => {
    if (!apiReady || !roots) return;

    // On first load, restore saved directory from localStorage
    if (!restoredRef.current && initialSavedCwd) {
      restoredRef.current = true;
      handleDirectorySelect(initialSavedCwd);
      return;
    }
    restoredRef.current = true;

    handleDirectorySelect(activeTab === "bundle" ? roots.bundle : roots.home);
  }, [apiReady, roots, activeTab, handleDirectorySelect, initialSavedCwd]);

  // Navigate to absolute path from params (e.g. opened from lsof)
  const handledParamsRef = useRef<string | null>(null);
  useEffect(() => {
    if (!apiReady || !roots || !params?.path?.startsWith("/")) return;
    if (handledParamsRef.current === params.path) return;
    handledParamsRef.current = params.path;
    if (params.path.startsWith(roots.bundle)) {
      setActiveTab("bundle");
    } else {
      setActiveTab("home");
    }
    handleDirectorySelect(params.path);
  }, [apiReady, roots, params?.path, handleDirectorySelect]);

  // Persist finder state to localStorage
  useEffect(() => {
    if (!storageKey || !fullCwd) return;
    try {
      localStorage.setItem(storageKey, JSON.stringify({ activeTab, fullCwd }));
    } catch {
      localStorage.removeItem(storageKey);
    }
  }, [storageKey, activeTab, fullCwd]);

  const isReadOnly = !cwdWritable;

  return (
    <>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleFileInputChange}
      />
      <ResizablePanelGroup orientation="horizontal" autoSaveId="finder-split">
        <ResizablePanel defaultSize="15%" minSize="5%" maxSize="80%">
          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as "bundle" | "home")}
            className="h-full flex flex-col"
          >
            <TabsList variant="line" className="w-full">
              <TabsTrigger value="home" className="flex-1">
                {t("home")}
              </TabsTrigger>
              {!isDaemon && (
                <TabsTrigger value="bundle" className="flex-1">
                  {isDroid ? "APK" : t("bundle")}
                </TabsTrigger>
              )}
            </TabsList>
            {!isDaemon && (
              <TabsContent
                value="bundle"
                className="flex-1 overflow-hidden mt-0"
              >
                {roots && (
                  <DirectoryTree
                    root="!"
                    rootPath={roots.bundle}
                    apiReady={apiReady}
                    loadDirectory={loadDirectory}
                    onDirectorySelect={handleDirectorySelect}
                    currentPath={activeTab === "bundle" ? fullCwd : null}
                  />
                )}
              </TabsContent>
            )}
            <TabsContent value="home" className="flex-1 overflow-hidden mt-0">
              {roots && (
                <DirectoryTree
                  root="~"
                  rootPath={roots.home}
                  apiReady={apiReady}
                  loadDirectory={loadDirectory}
                  onDirectorySelect={handleDirectorySelect}
                  currentPath={activeTab === "home" ? fullCwd : null}
                />
              )}
            </TabsContent>
          </Tabs>
        </ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel defaultSize="85%">
          <div
            className="h-full relative"
            onDragOver={(e) => {
              e.preventDefault();
              if (cwdWritable) setIsDragOver(true);
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
              onNavigate={handleNavigate}
              onRename={handleRename}
              onDelete={handleDelete}
              onBatchDelete={handleBatchDelete}
              onUpload={!isReadOnly ? handleUpload : undefined}
              onRefresh={
                fullCwd ? () => handleDirectorySelect(fullCwd) : undefined
              }
              isReadOnly={isReadOnly}
            />
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
      <Dialog
        open={uploadOpen}
        onOpenChange={(open) => {
          if (!open) uploadAbortRef.current = true;
          setUploadOpen(open);
        }}
      >
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
