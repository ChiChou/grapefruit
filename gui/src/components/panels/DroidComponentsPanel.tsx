import { useCallback, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Play, Radio, Search, ShieldCheck, Globe } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { toast } from "sonner";

import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from "@/components/ui/tooltip";
import { Spinner } from "@/components/ui/spinner";
import { useDroidQuery, useDroidMutation } from "@/lib/queries";

import type { ActivityEntry } from "@agent/droid/modules/activities";
import type { ServiceEntry } from "@agent/droid/modules/services";
import type { ReceiverEntry } from "@agent/droid/modules/receivers";

const ITEM_HEIGHT = 56;

type ComponentEntry = ActivityEntry | ServiceEntry | ReceiverEntry;

function shortName(fullName: string): string {
  const idx = fullName.lastIndexOf(".");
  return idx >= 0 ? fullName.substring(idx + 1) : fullName;
}

export function DroidComponentsPanel() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState("activities");
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: activities = [], isLoading: activitiesLoading } =
    useDroidQuery<ActivityEntry[]>(["activities"], (api) =>
      api.activities.list(),
    );

  const { data: services = [], isLoading: servicesLoading } = useDroidQuery<
    ServiceEntry[]
  >(["services"], (api) => api.services.list());

  const { data: receivers = [], isLoading: receiversLoading } =
    useDroidQuery<ReceiverEntry[]>(["receivers"], (api) =>
      api.receivers.list(),
    );

  const startActivityMutation = useDroidMutation<
    void,
    { component: string }
  >((api, { component }) => api.activities.start({ component }));

  const startServiceMutation = useDroidMutation<void, { component: string }>(
    (api, { component }) => api.services.start({ component }),
  );

  const sendBroadcastMutation = useDroidMutation<
    void,
    { component: string }
  >((api, { component }) => api.receivers.send({ component }));

  const filterItems = useCallback(<T extends ComponentEntry>(items: T[]): T[] => {
    if (!search.trim()) return items;
    const query = search.toLowerCase();
    return items.filter((item) => item.name.toLowerCase().includes(query));
  }, [search]);

  const filteredActivities = useMemo(
    () => filterItems(activities),
    [activities, filterItems],
  );
  const filteredServices = useMemo(
    () => filterItems(services),
    [filterItems, services],
  );
  const filteredReceivers = useMemo(
    () => filterItems(receivers),
    [filterItems, receivers],
  );

  const currentItems =
    activeTab === "activities"
      ? filteredActivities
      : activeTab === "services"
        ? filteredServices
        : filteredReceivers;

  const totalItems =
    activeTab === "activities"
      ? activities
      : activeTab === "services"
        ? services
        : receivers;

  const isLoading =
    activeTab === "activities"
      ? activitiesLoading
      : activeTab === "services"
        ? servicesLoading
        : receiversLoading;

  const virtualizer = useVirtualizer({
    count: currentItems.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ITEM_HEIGHT,
  });

  const handleAction = async (name: string) => {
    try {
      if (activeTab === "activities") {
        await startActivityMutation.mutateAsync({ component: name });
        toast.success(t("start_activity"), { description: name });
      } else if (activeTab === "services") {
        await startServiceMutation.mutateAsync({ component: name });
        toast.success(t("start_service"), { description: name });
      } else {
        await sendBroadcastMutation.mutateAsync({ component: name });
        toast.success(t("send_broadcast"), { description: name });
      }
    } catch (err) {
      toast.error((err as Error).message);
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList variant="line" className="w-full">
            <TabsTrigger value="activities" className="flex-1">
              {t("activities")}
            </TabsTrigger>
            <TabsTrigger value="services" className="flex-1">
              {t("services")}
            </TabsTrigger>
            <TabsTrigger value="receivers" className="flex-1">
              {t("receivers")}
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <div className="text-xs text-muted-foreground">
          {currentItems.length} / {totalItems.length}
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 min-h-0 h-full overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
            {t("loading")}...
          </div>
        ) : currentItems.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_components")}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vItem) => {
              const item = currentItems[vItem.index];
              return (
                <div
                  key={vItem.key}
                  className="absolute left-0 right-0 px-4 py-2 border-b border-border hover:bg-accent group"
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
                >
                  <div className="flex items-center justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium truncate">
                        {shortName(item.name)}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono truncate">
                        {item.name}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0 ml-2">
                      {item.exported && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <span className="text-muted-foreground shrink-0" />
                              }
                            >
                              <Globe className="h-3.5 w-3.5" />
                            </TooltipTrigger>
                            <TooltipContent>{t("exported")}</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                      {item.permission && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <span className="text-muted-foreground shrink-0" />
                              }
                            >
                              <ShieldCheck className="h-3.5 w-3.5" />
                            </TooltipTrigger>
                            <TooltipContent>{item.permission}</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                      {activeTab !== "services" && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <button
                                  type="button"
                                  className="p-1 rounded text-amber-700 dark:text-amber-400 opacity-0 group-hover:opacity-100 hover:bg-amber-100 dark:hover:bg-amber-900/50 transition-opacity"
                                  onClick={() => handleAction(item.name)}
                                />
                              }
                            >
                              {activeTab === "receivers" ? (
                                <Radio className="h-3.5 w-3.5" />
                              ) : (
                                <Play className="h-3.5 w-3.5" />
                              )}
                            </TooltipTrigger>
                            <TooltipContent>
                              {activeTab === "activities"
                                ? t("start_activity")
                                : t("send_broadcast")}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
