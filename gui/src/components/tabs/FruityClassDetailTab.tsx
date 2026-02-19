import { useMemo, useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import type { IDockviewPanelProps } from "dockview";
import { Anchor, Code, Layers, Loader2 } from "lucide-react";

import { useDock } from "@/context/DockContext";
import { useSession, Status, Mode } from "@/context/SessionContext";
import { useRepl } from "@/context/useRepl";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import Editor, { loader } from "@monaco-editor/react";
import { useTheme } from "@/components/providers/ThemeProvider";
import { header, type ClassDumpInfo } from "../../lib/classdump-header.ts";
import { useRpcQuery } from "@/lib/queries";
import {
  objc,
  formatObjCMethod,
  type ObjCHookTarget,
} from "@/lib/hook-template.ts";

import type { ClassDetail } from "@agent/fruity/modules/classdump";

loader.init().then((monaco) => {
  monaco.languages.register({ id: "objective-c" });
});

export interface ClassDetailParams {
  className: string;
}

export function FruityClassDetailTab({
  params,
}: IDockviewPanelProps<ClassDetailParams>) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { fruity, status, platform, mode, device, bundle, pid } = useSession();
  const { appendCode } = useRepl();
  const navigate = useNavigate();

  const hooksPath = `/workspace/${platform}/${device}/${mode}/${mode === Mode.App ? bundle : pid}/hooks`;
  const [showInherited, setShowInherited] = useState(false);
  const [methodSearch, setMethodSearch] = useState("");
  const [activeTab, setActiveTab] = useState("methods");
  const [protocolSearch, setProtocolSearch] = useState("");
  const [batchMode, setBatchMode] = useState(false);
  const [selectedMethods, setSelectedMethods] = useState<Set<string>>(
    new Set(),
  );

  const { data: classInfo, isLoading } = useRpcQuery<ClassDetail>(
    ["classDetail", params.className],
    (api) => api.classdump.inspect(params.className),
  );

  const openModuleTab = (path: string) => {
    const name = path.split("/").pop() || path;
    openFilePanel({
      id: `module_${path}`,
      component: "moduleDetail",
      title: name,
      params: { path },
    });
  };

  const openClassTab = (className: string) => {
    openFilePanel({
      id: `class_${className}`,
      component: "classDetail",
      title: className,
      params: { className },
    });
  };

  const openDisassemblyTab = (address: string, methodName: string) => {
    openFilePanel({
      id: `disasm_${address}`,
      component: "disassembly",
      title: methodName,
      params: { address, name: methodName },
    });
  };

  const ivarEntries = useMemo(() => classInfo?.ivars ?? [], [classInfo]);
  const ownMethodsSet = useMemo(
    () => new Set(classInfo?.ownMethods ?? []),
    [classInfo?.ownMethods],
  );
  const displayedMethods = useMemo(() => {
    if (!classInfo) return [];
    let allMethods = classInfo.methods;
    if (!showInherited) {
      allMethods = allMethods.filter((method) =>
        ownMethodsSet.has(method.name),
      );
    }
    if (methodSearch.trim()) {
      const query = methodSearch.toLowerCase();
      allMethods = allMethods.filter((method) =>
        method.name.toLowerCase().includes(query),
      );
    }
    return allMethods;
  }, [classInfo, showInherited, ownMethodsSet, methodSearch]);

  const filteredProtocols = useMemo(() => {
    if (!classInfo) return [];
    if (!protocolSearch.trim()) return classInfo.protocols;
    const query = protocolSearch.toLowerCase();
    return classInfo.protocols.filter((p) => p.toLowerCase().includes(query));
  }, [classInfo, protocolSearch]);

  const handleSelectMethod = useCallback(
    (methodName: string, checked: boolean) => {
      setSelectedMethods((prev) => {
        const next = new Set(prev);
        if (checked) {
          next.add(methodName);
        } else {
          next.delete(methodName);
        }
        return next;
      });
    },
    [],
  );

  const handleHookMethod = useCallback(
    async (methodName: string) => {
      if (!fruity || status !== Status.Ready || !classInfo) return;
      try {
        await fruity.objc.swizzle(classInfo.name, methodName);
        // Navigate to hooks panel, show toast, and trigger refresh
        navigate(hooksPath);
        toast.success(t("hook_added"), {
          description: formatObjCMethod(classInfo.name, methodName),
        });
        window.dispatchEvent(new CustomEvent("hooks:refresh"));
      } catch (error) {
        console.error("Failed to hook method:", error);
        toast.error(t("hook_failed"));
      }
    },
    [fruity, status, classInfo, navigate, hooksPath, t],
  );

  const handleGenerateCode = useCallback(
    (methodName: string) => {
      if (!classInfo) return;
      const target: ObjCHookTarget = {
        type: "objc",
        cls: classInfo.name,
        sel: methodName,
      };
      const code = objc(target);
      appendCode(code);
    },
    [classInfo, appendCode],
  );

  const handleBatchHook = useCallback(async () => {
    if (!fruity || status !== Status.Ready || !classInfo) return;

    let successCount = 0;
    for (const methodName of selectedMethods) {
      try {
        await fruity.objc.swizzle(classInfo.name, methodName);
        successCount++;
      } catch (error) {
        console.error(`Failed to hook ${methodName}:`, error);
      }
    }

    if (successCount > 0) {
      // Navigate to hooks panel, show toast, and trigger refresh
      navigate(hooksPath);
      toast.success(t("hook_added_count", { count: successCount }));
      window.dispatchEvent(new CustomEvent("hooks:refresh"));
      setSelectedMethods(new Set());
    }
  }, [fruity, status, classInfo, selectedMethods, navigate, hooksPath, t]);

  const handleBatchGenerateCode = useCallback(() => {
    if (!classInfo) return;

    const codes: string[] = [];
    for (const methodName of selectedMethods) {
      const target: ObjCHookTarget = {
        type: "objc",
        cls: classInfo.name,
        sel: methodName,
      };
      codes.push(objc(target));
    }

    if (codes.length > 0) {
      appendCode(codes.join("\n"));
    }
  }, [classInfo, selectedMethods, appendCode]);

  const toggleBatchMode = useCallback(() => {
    setBatchMode((prev) => !prev);
    setSelectedMethods(new Set());
  }, []);

  const selectedCount = selectedMethods.size;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (!classInfo) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-4 overflow-y-auto">
      <div className="flex flex-wrap justify-between gap-2 items-center mb-4 text-sm">
        <div className="flex flex-wrap gap-1 items-center">
          {classInfo.proto.map((cls) => (
            <span key={cls} className="flex items-center">
              <button
                type="button"
                className="text-amber-600 dark:text-amber-400 hover:underline cursor-pointer font-mono"
                onClick={() => openClassTab(cls)}
              >
                {cls}
              </button>
              <span className="mx-1 text-muted-foreground">/</span>
            </span>
          ))}
          <span className="font-mono font-semibold">{classInfo.name}</span>
        </div>
        <button
          type="button"
          className="text-sm text-amber-600 dark:text-amber-400 hover:underline cursor-pointer"
          onClick={() => openModuleTab(classInfo.module)}
        >
          {classInfo.module}
        </button>
      </div>

      <div className="flex-1 flex flex-col overflow-hidden">
        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="flex flex-col h-full"
        >
          <TabsList>
            <TabsTrigger value="methods">{t("methods")}</TabsTrigger>
            <TabsTrigger value="protocols">{t("protocols")}</TabsTrigger>
            <TabsTrigger value="ivar">ivar</TabsTrigger>
            <TabsTrigger value="classdump">classdump</TabsTrigger>
          </TabsList>

          <TabsContent value="methods" className="flex-1 overflow-hidden">
            <section className="h-full flex flex-col">
              <div className="flex flex-wrap items-center gap-2 mb-2">
                <h3 className="text-sm font-medium text-muted-foreground">
                  {t("methods")} ({displayedMethods.length})
                </h3>
                <div className="flex items-center gap-2 ml-auto">
                  <Button
                    variant={batchMode ? "secondary" : "outline"}
                    size="sm"
                    onClick={toggleBatchMode}
                    className="gap-1.5 h-7"
                  >
                    <Layers className="h-3.5 w-3.5" />
                    {t("hook_batch_mode")}
                  </Button>
                  <Checkbox
                    id={`show-inherited-${params.className}`}
                    checked={showInherited}
                    onCheckedChange={(checked) =>
                      setShowInherited(checked === true)
                    }
                  />
                  <Label
                    htmlFor={`show-inherited-${params.className}`}
                    className="text-xs cursor-pointer whitespace-nowrap"
                  >
                    {t("show_inherited")}
                  </Label>
                </div>
              </div>
              <Input
                placeholder={t("search")}
                value={methodSearch}
                onChange={(e) => setMethodSearch(e.target.value)}
                className="mb-2 h-8 text-sm"
              />

              {batchMode && (
                <div className="flex items-center gap-2 mb-2 p-2 bg-muted/50 rounded-md">
                  <span className="text-sm text-muted-foreground">
                    {t("hook_selected_count", { count: selectedCount })}
                  </span>
                  <div className="flex-1" />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleBatchHook}
                    disabled={status !== Status.Ready || selectedCount === 0}
                    className="gap-1.5 h-7"
                  >
                    <Anchor className="h-3.5 w-3.5" />
                    {t("hook_batch_hook")}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleBatchGenerateCode}
                    disabled={selectedCount === 0}
                    className="gap-1.5 h-7"
                  >
                    <Code className="h-3.5 w-3.5" />
                    {t("hook_batch_generate")}
                  </Button>
                </div>
              )}

              {displayedMethods.length > 0 ? (
                <div className="border rounded flex-1 overflow-auto min-h-0">
                  <div className="divide-y divide-border/50">
                    {displayedMethods.map(({ name: method, types, impl }) => (
                      <div key={method} className="p-2 hover:bg-muted/50 group">
                        <div className="flex items-start gap-2">
                          {batchMode ? (
                            <Checkbox
                              checked={selectedMethods.has(method)}
                              onCheckedChange={(checked) =>
                                handleSelectMethod(method, !!checked)
                              }
                              className="mt-0.5"
                              aria-label="Select method"
                            />
                          ) : (
                            <div className="flex items-center gap-0.5 shrink-0">
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                                onClick={() => handleHookMethod(method)}
                                disabled={status !== Status.Ready}
                                title={t("hook_add")}
                              >
                                <Anchor className="h-3.5 w-3.5" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                                onClick={() => handleGenerateCode(method)}
                                title={t("hook_generate_code")}
                              >
                                <Code className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                          )}
                          <div className="min-w-0 flex-1">
                            <div
                              className="font-mono text-xs truncate"
                              title={method}
                            >
                              {method}
                            </div>
                            <div
                              className="font-mono text-muted-foreground truncate text-[10px]"
                              title={types}
                            >
                              {types}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="font-mono text-xs text-primary hover:underline cursor-pointer shrink-0"
                            onClick={() => openDisassemblyTab(impl, method)}
                          >
                            {impl}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-sm text-muted-foreground py-4 text-center border rounded">
                  {t("no_results")}
                </div>
              )}
            </section>
          </TabsContent>

          <TabsContent value="protocols">
            <section className="flex-1 overflow-auto">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-muted-foreground">
                  {t("protocols")} ({filteredProtocols.length})
                </h3>
                <Input
                  placeholder={t("search")}
                  value={protocolSearch}
                  onChange={(e) => setProtocolSearch(e.target.value)}
                  className="w-48 h-8 text-xs"
                />
              </div>
              <div className="flex flex-wrap gap-2">
                {filteredProtocols.map((protocol) => (
                  <span
                    key={protocol}
                    className="text-xs font-mono bg-muted px-2 py-1 rounded"
                  >
                    {protocol}
                  </span>
                ))}
              </div>
              {filteredProtocols.length === 0 && (
                <div className="text-sm text-muted-foreground py-4 text-center">
                  {t("no_results")}
                </div>
              )}
            </section>
          </TabsContent>

          <TabsContent value="ivar">
            <section>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">
                ivar ({ivarEntries.length})
              </h3>
              <div className="overflow-auto max-h-48 border rounded">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-24">{t("offset")}</TableHead>
                      <TableHead>{t("name")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {ivarEntries.map(({ offset, name }) => (
                      <TableRow key={`${offset}-${name}`}>
                        <TableCell className="font-mono text-xs">
                          {offset}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {name}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </section>
          </TabsContent>

          <TabsContent value="classdump" className="flex-1 m-0 overflow-hidden">
            <Editor
              height="100%"
              language="objective-c"
              value={classInfo ? header(classInfo as ClassDumpInfo) : ""}
              theme={theme === "dark" ? "vs-dark" : "light"}
              options={{
                readOnly: true,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                wordWrap: "on",
                fontSize: 13,
                lineNumbers: "on",
                folding: true,
                automaticLayout: true,
              }}
            />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
