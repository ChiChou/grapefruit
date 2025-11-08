import { useState } from "react";
import { Link, Outlet, useParams } from "react-router";
import { t } from "i18next";
import { FileText, Terminal, Webhook } from "lucide-react";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { LanguageSelector } from "./LanguageSelector";
import { DarkmodeToggle } from "./DarkmodeToggle";

import logo from "../assets/logo.svg";

interface App {
  name: string;
  identifier: string;
  pid: number;
}

export function Workspace() {
  const { udid, identifier } = useParams();
  const [open, setOpen] = useState(false);

  return (
    <div className="flex h-screen flex-col">
      <header className="border-b bg-white dark:bg-accent p-2">
        <div className="flex items-center gap-4">
          <Link to="/">
            <img src={logo} alt={t("logo_alt")} className="h-6 w-40" />
          </Link>
          <div className="flex-1 max-w-md">
            <input
              type="text"
              placeholder={t("search_commands")}
              onClick={() => setOpen(true)}
              readOnly
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100 cursor-pointer"
            />
          </div>
          <div className="ml-auto flex items-center gap-3">
            <LanguageSelector />
            <DarkmodeToggle />
          </div>
        </div>
      </header>

      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder={t("search_commands")} />
        <CommandList>
          <CommandEmpty>{t("no_results")}</CommandEmpty>
          <CommandGroup heading={t("commands")}>
            <CommandItem>Command 1</CommandItem>
            <CommandItem>Command 2</CommandItem>
            <CommandItem>Command 3</CommandItem>
          </CommandGroup>
        </CommandList>
      </CommandDialog>

      <ResizablePanelGroup direction="horizontal">
        <ResizablePanel defaultSize={20}></ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel>
          <ResizablePanelGroup direction="vertical" className="h-full">
            <ResizablePanel defaultSize={30}>
              <Outlet />
            </ResizablePanel>
            <ResizableHandle />
            <ResizablePanel defaultSize={15}>
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
            </ResizablePanel>
          </ResizablePanelGroup>
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  );
}
