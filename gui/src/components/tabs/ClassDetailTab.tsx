import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";

import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
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

import type { ClassInfo } from "../../../../agent/src/fruity/modules/classdump.ts";

export interface ClassDetailParams {
  className: string;
}

export function ClassDetailTab({
  params,
}: IDockviewPanelProps<ClassDetailParams>) {
  const { api, status } = useSession();
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [isLoading, setIsLoading] = useState(false);
  const [classInfo, setClassInfo] = useState<ClassInfo | null>(null);
  const [showInherited, setShowInherited] = useState(false);

  useEffect(() => {
    if (status !== ConnectionStatus.Ready || !api) return;

    setIsLoading(true);
    api.classdump
      .inspect(params.className)
      .then((result) => setClassInfo(result as unknown as ClassInfo))
      .catch((err) => {
        console.error("Failed to load class info:", err);
        setClassInfo(null);
      })
      .finally(() => setIsLoading(false));
  }, [api, status, params.className]);

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

  const ivarEntries = useMemo(
    () => (classInfo ? Object.entries(classInfo.ivars) : []),
    [classInfo],
  );
  const ownMethodsSet = useMemo(
    () => new Set(classInfo?.own ?? []),
    [classInfo?.own],
  );
  const displayedMethods = useMemo(() => {
    if (!classInfo) return [];
    const allMethods = Object.entries(classInfo.methods);
    if (showInherited) {
      return allMethods;
    }
    return allMethods.filter(([method]) => ownMethodsSet.has(method));
  }, [classInfo, showInherited, ownMethodsSet]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (!classInfo) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-4 overflow-y-auto">
      <h2 className="text-xl font-semibold mb-4">{classInfo.name}</h2>

      <div className="space-y-6">
        {/* Module */}
        <section>
          <h3 className="text-sm font-medium text-gray-500 mb-1">
            {t("module")}
          </h3>
          <button
            type="button"
            className="text-sm text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
            onClick={() => openModuleTab(classInfo.module)}
          >
            {classInfo.module}
          </button>
        </section>

        {classInfo.proto.length > 0 && (
          <section>
            <h3 className="text-sm font-medium text-gray-500 mb-2">
              {t("super_classes")}
            </h3>
            <div className="flex flex-wrap gap-1 items-center">
              {classInfo.proto.map((cls, idx) => (
                <span key={cls} className="flex items-center">
                  <button
                    type="button"
                    className="text-sm text-blue-600 dark:text-blue-400 hover:underline cursor-pointer font-mono"
                    onClick={() => openClassTab(cls)}
                  >
                    {cls}
                  </button>
                  {idx < classInfo.proto.length - 1 && (
                    <span className="mx-1 text-gray-400">→</span>
                  )}
                </span>
              ))}
            </div>
          </section>
        )}

        {/* Protocols */}
        {classInfo.protocols.length > 0 && (
          <section>
            <h3 className="text-sm font-medium text-gray-500 mb-2">
              {t("protocols")}
            </h3>
            <div className="flex flex-wrap gap-2">
              {classInfo.protocols.map((protocol) => (
                <span
                  key={protocol}
                  className="text-xs font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded"
                >
                  {protocol}
                </span>
              ))}
            </div>
          </section>
        )}

        {/* Instance Variables */}
        {ivarEntries.length > 0 && (
          <section>
            <h3 className="text-sm font-medium text-gray-500 mb-2">
              {t("instance_variables")} ({ivarEntries.length})
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
                  {ivarEntries.map(([offset, name]) => (
                    <TableRow key={offset}>
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

        {/* Methods */}
        {displayedMethods.length > 0 && (
          <section>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-gray-500">
                {t("methods")} ({displayedMethods.length})
              </h3>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id={`show-inherited-${params.className}`}
                  checked={showInherited}
                  onCheckedChange={(checked) =>
                    setShowInherited(checked === true)
                  }
                />
                <Label
                  htmlFor={`show-inherited-${params.className}`}
                  className="text-sm cursor-pointer"
                >
                  {t("show_inherited")}
                </Label>
              </div>
            </div>
            <div className="border rounded">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("method")}</TableHead>
                    <TableHead>{t("address")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displayedMethods.map(([method, addr]) => (
                    <TableRow key={method}>
                      <TableCell className="font-mono text-xs">
                        {method}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {addr}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
