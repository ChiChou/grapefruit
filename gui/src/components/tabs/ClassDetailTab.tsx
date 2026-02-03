import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";

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
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import Editor, { loader } from "@monaco-editor/react";
import { useTheme } from "@/components/theme-provider";
import { header, type ClassDumpInfo } from "../../lib/classdump-header.ts";
import { useRpcQuery } from "@/lib/queries";

import type { ClassDetail } from "../../../../agent/types/fruity/modules/classdump";

loader.init().then((monaco) => {
  monaco.languages.register({ id: "objective-c" });
});

export interface ClassDetailParams {
  className: string;
}

export function ClassDetailTab({
  params,
}: IDockviewPanelProps<ClassDetailParams>) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [showInherited, setShowInherited] = useState(false);
  const [methodSearch, setMethodSearch] = useState("");
  const [activeTab, setActiveTab] = useState("methods");
  const [protocolSearch, setProtocolSearch] = useState("");

  const { data: classInfo, isLoading } = useRpcQuery<ClassDetail>(
    ["classDetail", params.className],
    (api) => api.classdump.inspect(params.className)
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
      <div className="flex flex-wrap justify-between gap-2 items-center mb-4 text-sm">
        <div className="flex flex-wrap gap-1 items-center">
          {classInfo.proto.map((cls) => (
            <span key={cls} className="flex items-center">
              <button
                type="button"
                className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer font-mono"
                onClick={() => openClassTab(cls)}
              >
                {cls}
              </button>
              <span className="mx-1 text-gray-400">/</span>
            </span>
          ))}
          <span className="font-mono font-semibold">{classInfo.name}</span>
        </div>
        <button
          type="button"
          className="text-sm text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
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

          <TabsContent value="methods">
            <section className="flex-1 overflow-auto">
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
              <Input
                placeholder={t("search")}
                value={methodSearch}
                onChange={(e) => setMethodSearch(e.target.value)}
                className="mb-2"
              />
              {displayedMethods.length > 0 ? (
                <div className="border rounded max-h-[calc(100vh-300px)] overflow-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t("method")}</TableHead>
                        <TableHead>{t("type_encoding")}</TableHead>
                        <TableHead>{t("address")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {displayedMethods.map(({ name: method, types, impl }) => (
                        <TableRow key={method}>
                          <TableCell className="font-mono text-xs">
                            {method}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-gray-500">
                            {types}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {impl}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="text-sm text-gray-500 py-4 text-center border rounded">
                  {t("no_results")}
                </div>
              )}
            </section>
          </TabsContent>

          <TabsContent value="protocols">
            <section className="flex-1 overflow-auto">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-500">
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
                    className="text-xs font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded"
                  >
                    {protocol}
                  </span>
                ))}
              </div>
              {filteredProtocols.length === 0 && (
                <div className="text-sm text-gray-500 py-4 text-center">
                  {t("no_results")}
                </div>
              )}
            </section>
          </TabsContent>

          <TabsContent value="ivar">
            <section>
              <h3 className="text-sm font-medium text-gray-500 mb-2">
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
