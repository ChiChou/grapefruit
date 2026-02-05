import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { ImportsListView } from "../views/ImportsListView";
import { SectionsListView } from "../views/SectionsListView";
import { ClassesListView } from "../views/ClassesListView";
import { SymbolsListView } from "../views/SymbolsListView";
import { ExportedListView } from "../views/ExportedListView";

export interface ModuleDetailParams {
  path: string;
}

type TabKey = "imports" | "sections" | "symbols" | "exported" | "classes";

export function ModuleDetailTab({
  params,
}: IDockviewPanelProps<ModuleDetailParams>) {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<TabKey>("sections");

  const handleTabChange = (value: string) => {
    setActiveTab(value as TabKey);
  };

  return (
    <div className="h-full flex flex-col p-4 overflow-y-auto">
      <Tabs
        defaultValue="sections"
        value={activeTab}
        onValueChange={handleTabChange}
        className="flex-1 flex flex-col"
      >
        <div className="flex items-center justify-between gap-4 mb-2">
          <TabsList>
            <TabsTrigger value="imports">{t("imports")}</TabsTrigger>
            <TabsTrigger value="sections">{t("sections")}</TabsTrigger>
            <TabsTrigger value="classes">{t("classes")}</TabsTrigger>
            <TabsTrigger value="symbols">{t("symbols")}</TabsTrigger>
            <TabsTrigger value="exported">{t("exported")}</TabsTrigger>
          </TabsList>
          <h2 className="text-sm font-thin truncate">{params.path}</h2>
        </div>
        <TabsContent value="imports" className="flex-1">
          <ImportsListView path={params.path} />
        </TabsContent>
        <TabsContent value="sections" className="flex-1">
          <SectionsListView path={params.path} />
        </TabsContent>
        <TabsContent value="classes" className="flex-1">
          <ClassesListView path={params.path} />
        </TabsContent>
        <TabsContent value="symbols" className="flex-1">
          <SymbolsListView path={params.path} />
        </TabsContent>
        <TabsContent value="exported" className="flex-1">
          <ExportedListView path={params.path} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
