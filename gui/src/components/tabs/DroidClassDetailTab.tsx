import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Search, Loader2, Code2 } from "lucide-react";

import { useDock } from "@/context/DockContext";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useDroidQuery } from "@/lib/queries";
import { useRepl } from "@/context/useRepl";
import { java, javaBatch } from "@/lib/codegen/hookjs.ts";

import type { JavaClassDetail, JavaMethod } from "@agent/droid/modules/classes";

export interface JavaClassDetailParams {
  className: string;
}

export function DroidClassDetailTab({
  params,
}: IDockviewPanelProps<JavaClassDetailParams>) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const { appendCode } = useRepl();

  const [activeTab, setActiveTab] = useState("methods");
  const [methodSearch, setMethodSearch] = useState("");
  const [fieldSearch, setFieldSearch] = useState("");
  const [selectedMethods, setSelectedMethods] = useState<Set<number>>(
    () => new Set(),
  );

  const { data: classInfo, isLoading } = useDroidQuery<JavaClassDetail>(
    ["javaClassDetail", params.className],
    (api) => api.classes.inspect(params.className),
  );

  const openClassTab = (className: string) => {
    openFilePanel({
      id: `javaclass_${className}`,
      component: "javaClassDetail",
      title: className,
      params: { className },
    });
  };

  const displayedMethods = useMemo(() => {
    if (!classInfo) return [] as { method: JavaMethod; index: number }[];
    const items = classInfo.methods.map((method, index) => ({ method, index }));
    if (!methodSearch.trim()) return items;
    const query = methodSearch.toLowerCase();
    return items.filter(({ method }) =>
      method.name.toLowerCase().includes(query),
    );
  }, [classInfo, methodSearch]);

  const allDisplayedSelected =
    displayedMethods.length > 0 &&
    displayedMethods.every(({ index }) => selectedMethods.has(index));

  const toggleSelectAll = (checked: boolean) => {
    setSelectedMethods((prev) => {
      const next = new Set(prev);
      for (const { index } of displayedMethods) {
        if (checked) next.add(index);
        else next.delete(index);
      }
      return next;
    });
  };

  const toggleMethod = (index: number) => {
    setSelectedMethods((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  };

  const generateHooks = () => {
    if (!classInfo || selectedMethods.size === 0) return;
    const methods = [...selectedMethods]
      .sort((a, b) => a - b)
      .map((i) => classInfo.methods[i]);
    const code = javaBatch(classInfo.name, methods);
    appendCode(code);
  };

  const displayedFields = useMemo(() => {
    if (!classInfo) return [];
    let fields = classInfo.fields;
    if (fieldSearch.trim()) {
      const query = fieldSearch.toLowerCase();
      fields = fields.filter((f) => f.name.toLowerCase().includes(query));
    }
    return fields;
  }, [classInfo, fieldSearch]);

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
      {/* Header: superclass chain + interfaces */}
      <div className="flex flex-wrap gap-2 items-center mb-4 text-sm">
        <div className="flex flex-wrap gap-1 items-center">
          {classInfo.superClass && (
            <span className="flex items-center">
              <button
                type="button"
                className="text-amber-600 dark:text-amber-400 hover:underline cursor-pointer font-mono"
                onClick={() => openClassTab(classInfo.superClass!)}
              >
                {classInfo.superClass}
              </button>
              <span className="mx-1 text-muted-foreground">/</span>
            </span>
          )}
          <span className="font-mono font-semibold">{classInfo.name}</span>
        </div>
        {classInfo.interfaces.length > 0 && (
          <div className="flex flex-wrap gap-1 items-center ml-2">
            {classInfo.interfaces.map((iface) => (
              <Badge
                key={iface}
                variant="secondary"
                className="font-mono text-[10px] px-1.5 py-0"
              >
                {iface}
              </Badge>
            ))}
          </div>
        )}
      </div>

      <div className="flex-1 flex flex-col overflow-hidden">
        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="h-full flex flex-col"
        >
          <TabsContent value="methods" className="overflow-hidden">
            <section className="h-full flex flex-col">
              <div className="flex items-center gap-2 mb-2">
                <Checkbox
                  checked={allDisplayedSelected}
                  onCheckedChange={toggleSelectAll}
                />
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder={t("search")}
                    value={methodSearch}
                    onChange={(e) => setMethodSearch(e.target.value)}
                    className="pl-9 h-8 text-sm"
                  />
                </div>
                {selectedMethods.size > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="shrink-0"
                    onClick={generateHooks}
                  >
                    <Code2 className="h-3.5 w-3.5" />
                    Hook ({selectedMethods.size})
                  </Button>
                )}
              </div>
              {displayedMethods.length > 0 ? (
                <div className="border rounded flex-1 overflow-auto min-h-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8" />
                        <TableHead className="w-8" />
                        <TableHead>{t("name")}</TableHead>
                        <TableHead>{t("return_type")}</TableHead>
                        <TableHead>{t("parameters")}</TableHead>
                        <TableHead className="w-8" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {displayedMethods.map(({ method, index }) => (
                        <TableRow key={index}>
                          <TableCell className="text-center">
                            <Checkbox
                              checked={selectedMethods.has(index)}
                              onCheckedChange={() => toggleMethod(index)}
                            />
                          </TableCell>
                          <TableCell className="text-center">
                            {method.isStatic && (
                              <Badge
                                variant="outline"
                                className="text-[10px] px-1"
                              >
                                static
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {method.name}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {method.returnType}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {method.argumentTypes.join(", ") || "-"}
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 px-1.5"
                              onClick={() =>
                                appendCode(
                                  java({
                                    type: "java",
                                    cls: classInfo!.name,
                                    name: method.name,
                                    argumentTypes: method.argumentTypes,
                                    returnType: method.returnType,
                                  }),
                                )
                              }
                            >
                              <Code2 className="h-3.5 w-3.5" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="text-sm text-muted-foreground py-4 text-center border rounded">
                  {t("no_results")}
                </div>
              )}
            </section>
          </TabsContent>

          <TabsContent value="fields" className="overflow-hidden">
            <section className="h-full flex flex-col">
              <div className="relative mb-2">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={t("search")}
                  value={fieldSearch}
                  onChange={(e) => setFieldSearch(e.target.value)}
                  className="pl-9 h-8 text-sm"
                />
              </div>
              {displayedFields.length > 0 ? (
                <div className="border rounded flex-1 overflow-auto min-h-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8" />
                        <TableHead>{t("name")}</TableHead>
                        <TableHead>{t("type")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {displayedFields.map((field) => (
                        <TableRow key={field.name}>
                          <TableCell className="text-center">
                            {field.isStatic && (
                              <Badge
                                variant="outline"
                                className="text-[10px] px-1"
                              >
                                static
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {field.name}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {field.type}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="text-sm text-muted-foreground py-4 text-center border rounded">
                  {t("no_results")}
                </div>
              )}
            </section>
          </TabsContent>

          <TabsList variant="line">
            <TabsTrigger value="methods">
              {t("methods")} ({classInfo.methods.length})
            </TabsTrigger>
            <TabsTrigger value="fields">
              {t("fields")} ({classInfo.fields.length})
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </div>
    </div>
  );
}
