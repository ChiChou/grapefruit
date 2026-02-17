import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Play, Square, Radio, Search, ShieldCheck } from "lucide-react";
import { List, type RowComponentProps } from "react-window";
import { toast } from "sonner";

import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from "@/components/ui/tooltip";
import { useDroidRpcQuery, useDroidRpcMutation } from "@/lib/queries";

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

  const { data: activities = [], isLoading: activitiesLoading } =
    useDroidRpcQuery<ActivityEntry[]>(["activities"], (api) =>
      api.activities.list(),
    );

  const { data: services = [], isLoading: servicesLoading } = useDroidRpcQuery<
    ServiceEntry[]
  >(["services"], (api) => api.services.list());

  const { data: receivers = [], isLoading: receiversLoading } =
    useDroidRpcQuery<ReceiverEntry[]>(["receivers"], (api) =>
      api.receivers.list(),
    );

  const startActivityMutation = useDroidRpcMutation<
    void,
    { component: string }
  >((api, { component }) => api.activities.start({ component }));

  const startServiceMutation = useDroidRpcMutation<void, { component: string }>(
    (api, { component }) => api.services.start({ component }),
  );

  const stopServiceMutation = useDroidRpcMutation<
    boolean,
    { component: string }
  >((api, { component }) => api.services.stop({ component }));

  const sendBroadcastMutation = useDroidRpcMutation<
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

  const handleAction = async (name: string) => {
    try {
      if (activeTab === "activities") {
        await startActivityMutation.mutateAsync({ component: name });
        toast.success(t("start_activity"));
      } else if (activeTab === "services") {
        await startServiceMutation.mutateAsync({ component: name });
        toast.success(t("start_service"));
      } else {
        await sendBroadcastMutation.mutateAsync({ component: name });
        toast.success(t("send_broadcast"));
      }
    } catch (err) {
      toast.error((err as Error).message);
    }
  };

  const handleStopService = async (name: string) => {
    try {
      await stopServiceMutation.mutateAsync({ component: name });
      toast.success(t("stop_service"));
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
          <TabsList className="w-full">
            <TabsTrigger value="activities" className="flex-1">
              {t("activities")} ({activities.length})
            </TabsTrigger>
            <TabsTrigger value="services" className="flex-1">
              {t("services")} ({services.length})
            </TabsTrigger>
            <TabsTrigger value="receivers" className="flex-1">
              {t("receivers")} ({receivers.length})
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <div className="text-xs text-muted-foreground">
          {currentItems.length} / {totalItems.length}
        </div>
      </div>
      <div className="flex-1 min-h-0 h-full">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("loading")}...
          </div>
        ) : currentItems.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_components")}
          </div>
        ) : (
          <div className="flex h-full">
            <List
              rowComponent={ComponentRow}
              rowCount={currentItems.length}
              rowHeight={ITEM_HEIGHT}
              rowProps={{
                items: currentItems,
                activeTab,
                onAction: handleAction,
                onStopService: handleStopService,
                t,
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function ComponentRow({
  index,
  style,
  items,
  activeTab,
  onAction,
  onStopService,
  t,
}: RowComponentProps<{
  items: ComponentEntry[];
  activeTab: string;
  onAction: (name: string) => void;
  onStopService: (name: string) => void;
  t: (key: string) => string;
}>) {
  const item = items[index];

  return (
    <div
      className="px-4 py-2 border-b border-border hover:bg-accent group"
      style={style}
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
            <Badge variant="secondary" className="text-[10px] px-1.5">
              {t("exported")}
            </Badge>
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
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger
                render={
                  <button
                    type="button"
                    className="p-1 rounded text-amber-700 dark:text-amber-400 opacity-0 group-hover:opacity-100 hover:bg-amber-100 dark:hover:bg-amber-900/50 transition-opacity"
                    onClick={() => onAction(item.name)}
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
                  : activeTab === "services"
                    ? t("start_service")
                    : t("send_broadcast")}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
          {activeTab === "services" && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger
                  render={
                    <button
                      type="button"
                      className="p-1 rounded text-red-700 dark:text-red-400 opacity-0 group-hover:opacity-100 hover:bg-red-100 dark:hover:bg-red-900/50 transition-opacity"
                      onClick={() => onStopService(item.name)}
                    />
                  }
                >
                  <Square className="h-3.5 w-3.5" />
                </TooltipTrigger>
                <TooltipContent>{t("stop_service")}</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>
      </div>
    </div>
  );
}
