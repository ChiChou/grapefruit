import { useMemo, useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import type { IDockviewPanelProps } from "dockview";
import { Anchor, Code, Loader2, Search } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

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
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useRpcQuery } from "@/lib/queries";
import {
  objc,
  formatObjCMethod,
  type ObjCHookTarget,
} from "@/lib/hook-template.ts";

import type { ClassDetail } from "@agent/fruity/modules/classdump";

export interface ClassDetailParams {
  className: string;
}

const METHOD_ROW_HEIGHT = 32;

interface MethodRowProps {
  methods: ClassDetail["methods"];
  selectedMethods: Set<string>;
  onSelect: (name: string, checked: boolean) => void;
  onHook: (name: string) => void;
  onGenerate: (name: string) => void;
  onDisasm: (address: string, name: string) => void;
  hookDisabled: boolean;
  hookAddLabel: string;
  generateLabel: string;
}

function MethodRow({
  index,
  style,
  methods,
  selectedMethods,
  onSelect,
  onHook,
  onGenerate,
  onDisasm,
  hookDisabled,
  hookAddLabel,
  generateLabel,
}: RowComponentProps<MethodRowProps>) {
  const { name: method, types, impl } = methods[index];

  return (
    <div
      className="px-2 hover:bg-muted/50 group flex items-center gap-2"
      style={style}
    >
      <Checkbox
        checked={selectedMethods.has(method)}
        onCheckedChange={(checked) => onSelect(method, !!checked)}
        aria-label={`Select ${method}`}
      />
      <div className="min-w-0 flex-1 flex items-center gap-2">
        <span className="font-mono text-sm truncate ml-1" title={method}>
          {method}
        </span>
        <span
          className="font-mono text-muted-foreground truncate text-xs shrink-0"
          title={types}
        >
          {types}
        </span>
      </div>
      <div className="flex items-center gap-0.5 shrink-0">
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={() => onHook(method)}
          disabled={hookDisabled}
          title={hookAddLabel}
        >
          <Anchor className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={() => onGenerate(method)}
          title={generateLabel}
        >
          <Code className="h-3.5 w-3.5" />
        </Button>
      </div>
      <button
        type="button"
        className="font-mono text-xs text-primary hover:underline cursor-pointer shrink-0"
        onClick={() => onDisasm(impl, method)}
      >
        {impl}
      </button>
    </div>
  );
}

export function FruityClassDetailTab({
  params,
}: IDockviewPanelProps<ClassDetailParams>) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const { fruity, status, platform, mode, device, bundle, pid } = useSession();
  const { appendCode } = useRepl();
  const navigate = useNavigate();

  const hooksPath = `/workspace/${platform}/${device}/${mode}/${mode === Mode.App ? bundle : pid}/hooks`;
  const [showInherited, setShowInherited] = useState(false);
  const [methodSearch, setMethodSearch] = useState("");
  const [selectedMethods, setSelectedMethods] = useState<Set<string>>(
    new Set(),
  );
  const [isHooking, setIsHooking] = useState(false);

  const { data: classInfo, isLoading } = useRpcQuery<ClassDetail>(
    ["classDetail", params.className],
    (api) => api.classdump.inspect(params.className),
  );

  const openClassTab = (className: string) => {
    openFilePanel({
      id: `class_${className}`,
      component: "classDetail",
      title: className,
      params: { className },
    });
  };

  const openDisassemblyTab = useCallback(
    (address: string, methodName: string) => {
      openFilePanel({
        id: `disasm_${address}`,
        component: "disassembly",
        title: methodName,
        params: { address, name: methodName },
      });
    },
    [openFilePanel],
  );

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

  const handleHookMethod = useCallback(
    async (methodName: string) => {
      if (!fruity || status !== Status.Ready || !classInfo) return;
      try {
        await fruity.objc.swizzle(classInfo.name, methodName);
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

  const handleSelectMethod = useCallback(
    (methodName: string, checked: boolean) => {
      setSelectedMethods((prev) => {
        const next = new Set(prev);
        if (checked) next.add(methodName);
        else next.delete(methodName);
        return next;
      });
    },
    [],
  );

  const handleSelectAll = useCallback(
    (checked: boolean) => {
      if (checked) {
        setSelectedMethods(new Set(displayedMethods.map((m) => m.name)));
      } else {
        setSelectedMethods(new Set());
      }
    },
    [displayedMethods],
  );

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
    if (codes.length > 0) appendCode(codes.join("\n"));
  }, [classInfo, selectedMethods, appendCode]);

  const handleBatchHook = useCallback(async () => {
    if (!fruity || status !== Status.Ready || !classInfo) return;
    setIsHooking(true);
    try {
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
        navigate(hooksPath);
        toast.success(t("hook_added_count", { count: successCount }));
        window.dispatchEvent(new CustomEvent("hooks:refresh"));
        setSelectedMethods(new Set());
      }
    } finally {
      setIsHooking(false);
    }
  }, [fruity, status, classInfo, selectedMethods, navigate, hooksPath, t]);

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
      <div className="flex items-center justify-center h-full text-destructive">
        {t("failed_to_load_class")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-4">
      <div className="mb-2 text-sm">
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
        <div className="text-xs text-muted-foreground font-mono mt-0.5 truncate" title={classInfo.module}>
          {classInfo.module}
        </div>
      </div>

      <div className="flex-1 flex gap-4 min-h-0">
        {/* Left: Methods */}
        <section className="flex-1 flex flex-col min-w-0">
          <div className="flex items-center gap-2 mb-1 px-2">
            <Checkbox
              checked={
                displayedMethods.length > 0 &&
                displayedMethods.every((m) =>
                  selectedMethods.has(m.name),
                )
              }
              onCheckedChange={(checked) => handleSelectAll(!!checked)}
              aria-label="Select all"
            />
            <h3 className="text-xs font-medium text-muted-foreground">
              {t("methods")} ({displayedMethods.length})
            </h3>
            {selectedCount > 0 && (
              <span className="text-xs text-muted-foreground">
                {selectedCount} {t("selected")}
              </span>
            )}
            <div className="flex-1" />
            <Button
              variant="outline"
              size="sm"
              onClick={handleBatchHook}
              disabled={
                status !== Status.Ready ||
                selectedCount === 0 ||
                isHooking
              }
              className="gap-1.5 h-7"
            >
              {isHooking ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Anchor className="h-3.5 w-3.5" />
              )}
              {t("hook_add")}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleBatchGenerateCode}
              disabled={selectedCount === 0}
              className="gap-1.5 h-7"
            >
              <Code className="h-3.5 w-3.5" />
              {t("hook_generate_code")}
            </Button>
            <label className="flex items-center gap-1.5 text-xs cursor-pointer">
              <Switch
                checked={showInherited}
                onCheckedChange={setShowInherited}
              />
              {t("show_inherited")}
            </label>
            <div className="relative w-48 shrink-0">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t("search")}
                value={methodSearch}
                onChange={(e) => setMethodSearch(e.target.value)}
                className="pl-9 h-8 text-sm"
              />
            </div>
          </div>

          {displayedMethods.length > 0 ? (
            <div className="flex-1 min-h-0">
              <List
                rowComponent={MethodRow}
                rowCount={displayedMethods.length}
                rowHeight={METHOD_ROW_HEIGHT}
                rowProps={{
                  methods: displayedMethods,
                  selectedMethods,
                  onSelect: handleSelectMethod,
                  onHook: handleHookMethod,
                  onGenerate: handleGenerateCode,
                  onDisasm: openDisassemblyTab,
                  hookDisabled: status !== Status.Ready,
                  hookAddLabel: t("hook_add"),
                  generateLabel: t("hook_generate_code"),
                }}
              />
            </div>
          ) : (
            <div className="text-sm text-muted-foreground py-4 text-center">
              {t("no_results")}
            </div>
          )}
        </section>

        {/* Right: Protocols & Ivars */}
        {(classInfo.protocols.length > 0 || ivarEntries.length > 0) && (
          <aside className="w-64 shrink-0 flex flex-col gap-3 overflow-y-auto">
            {classInfo.protocols.length > 0 && (
              <section>
                <h3 className="text-xs font-medium text-muted-foreground mb-1">
                  {t("protocols")} ({classInfo.protocols.length})
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {classInfo.protocols.map((protocol) => (
                    <span
                      key={protocol}
                      className="text-xs font-mono bg-muted px-2 py-0.5 rounded"
                    >
                      {protocol}
                    </span>
                  ))}
                </div>
              </section>
            )}

            {ivarEntries.length > 0 && (
              <section>
                <h3 className="text-xs font-medium text-muted-foreground mb-1">
                  ivar ({ivarEntries.length})
                </h3>
                <div className="border rounded">
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
            )}
          </aside>
        )}
      </div>
    </div>
  );
}
