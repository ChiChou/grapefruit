import { useEffect } from "react";
import { Link, Outlet, useParams } from "react-router";
import { t } from "i18next";
import { FileText, Terminal, Webhook } from "lucide-react";
import io from "socket.io-client";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DarkmodeToggle } from "./DarkmodeToggle";
import { LanguageSelector } from "./LanguageSelector";

import logo from "../assets/logo.svg";
import createRPC from "@/lib/rpc";

export function Workspace() {
  const { device, bundle } = useParams();

  useEffect(() => {
    const socket = io(`/session`, {
      query: { device, bundle },
    });

    const rpc = createRPC(socket);

    socket.on("connect", () => {
      console.log("Connected to workspace events socket");
    });

    socket.on("disconnect", () => {
      console.log("Disconnected from workspace events socket");
    });

    socket.on("ready", async () => {
      // test call
      console.info(await rpc.lsof.fds());
      const xml = await rpc.entitlements.xml();
      console.info(xml);
    });

    return () => {
      socket.disconnect();
    };
  }, [device, bundle]);

  return (
    <div className="flex h-screen flex-col">
      <ResizablePanelGroup direction="horizontal" className="h-full">
        <ResizablePanel defaultSize={20} className="flex flex-col">
          <div className="flex-1 p-4 space-y-4">
            <div className="mb-4 flex items-center justify-center gap-2 px-4">
              <Link to="/">
                <img src={logo} alt={t("logo_alt")} className="h-10 w-40" />
              </Link>
            </div>
          </div>
          <div className="p-4 flex gap-3">
            <LanguageSelector />
            <DarkmodeToggle />
          </div>
        </ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel>
          <ResizablePanelGroup direction="vertical" className="h-full">
            <ResizablePanel>
              <Outlet />
            </ResizablePanel>
            <ResizableHandle />
            <ResizablePanel defaultSize={30}>
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
