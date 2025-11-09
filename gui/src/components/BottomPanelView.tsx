import { t } from "i18next";
import { FileText, Terminal, Webhook } from "lucide-react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import type { WorkspacePanelPros } from "./panel-props";

export function BottomPanelView({ device, bundle }: WorkspacePanelPros) {
  return (
    <Tabs defaultValue="logs" className="h-full flex flex-col">
      <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0">
        <TabsTrigger
          value="logs"
          className="rounded-none border-1-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <FileText className="h-4 w-4" />
          {t("logs")}
        </TabsTrigger>
        <TabsTrigger
          value="shell"
          className="rounded-none border-1-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Terminal className="h-4 w-4" />
          {t("shell")}
        </TabsTrigger>
        <TabsTrigger
          value="hooks"
          className="rounded-none border-1-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Webhook className="h-4 w-4" />
          {t("hooks")}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="logs" className="flex-1 p-4"></TabsContent>
      <TabsContent value="shell" className="flex-1 p-4"></TabsContent>
      <TabsContent value="hooks" className="flex-1 p-4"></TabsContent>
    </Tabs>
  );
}
