import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Search } from "lucide-react";

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
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useDroidRpcQuery } from "@/lib/queries";

import type { JavaClassDetail } from "@agent/droid/modules/classes";

export interface JavaClassDetailParams {
  className: string;
}

export function DroidClassDetailTab({
  params,
}: IDockviewPanelProps<JavaClassDetailParams>) {
  const { openFilePanel } = useDock();
  const { t } = useTranslation();

  const [activeTab, setActiveTab] = useState("methods");
  const [methodSearch, setMethodSearch] = useState("");
  const [fieldSearch, setFieldSearch] = useState("");

  const { data: classInfo, isLoading } = useDroidRpcQuery<JavaClassDetail>(
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
    if (!classInfo) return [];
    let methods = classInfo.methods;
    if (methodSearch.trim()) {
      const query = methodSearch.toLowerCase();
      methods = methods.filter((m) =>
        m.name.toLowerCase().includes(query),
      );
    }
    return methods;
  }, [classInfo, methodSearch]);

  const displayedFields = useMemo(() => {
    if (!classInfo) return [];
    let fields = classInfo.fields;
    if (fieldSearch.trim()) {
      const query = fieldSearch.toLowerCase();
      fields = fields.filter((f) =>
        f.name.toLowerCase().includes(query),
      );
    }
    return fields;
  }, [classInfo, fieldSearch]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("loading")}...
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
      </div>

      {classInfo.interfaces.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          {classInfo.interfaces.map((iface) => (
            <Badge key={iface} variant="secondary" className="font-mono text-xs">
              {iface}
            </Badge>
          ))}
        </div>
      )}

      <div className="flex-1 flex flex-col overflow-hidden">
        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="flex flex-col h-full"
        >
          <TabsList>
            <TabsTrigger value="methods">
              {t("methods")} ({classInfo.methods.length})
            </TabsTrigger>
            <TabsTrigger value="fields">
              {t("fields")} ({classInfo.fields.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="methods" className="flex-1 overflow-hidden">
            <section className="h-full flex flex-col">
              <div className="relative mb-2">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={t("search")}
                  value={methodSearch}
                  onChange={(e) => setMethodSearch(e.target.value)}
                  className="pl-9 h-8 text-sm"
                />
              </div>
              {displayedMethods.length > 0 ? (
                <div className="border rounded flex-1 overflow-auto min-h-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8" />
                        <TableHead>{t("name")}</TableHead>
                        <TableHead>{t("return_type")}</TableHead>
                        <TableHead>{t("parameters")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {displayedMethods.map((method, i) => (
                        <TableRow key={`${method.name}-${i}`}>
                          <TableCell className="text-center">
                            {method.isStatic && (
                              <Badge variant="outline" className="text-[10px] px-1">S</Badge>
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

          <TabsContent value="fields" className="flex-1 overflow-hidden">
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
                              <Badge variant="outline" className="text-[10px] px-1">S</Badge>
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
        </Tabs>
      </div>
    </div>
  );
}
