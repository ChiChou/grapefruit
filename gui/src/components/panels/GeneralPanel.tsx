import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Check } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import { Status, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { useRpcQuery } from "@/lib/queries";

import type { BasicInfo } from "../../../../agent/types/fruity/modules/info";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="ml-2 p-1 text-muted-foreground hover:text-muted-foreground dark:hover:text-muted-foreground"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-3 h-3 text-green-500" />
      ) : (
        <Copy className="w-3 h-3" />
      )}
    </button>
  );
}

function PathDisplay({ path, onClick }: { path: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-left flex items-start text-sm font-mono break-all hover:text-amber-600 dark:hover:text-amber-400 transition-colors cursor-pointer hover:underline"
    >
      <span className="text-xs">{path}</span>
    </button>
  );
}

export function GeneralPanel() {
  const { t } = useTranslation();
  const { status, device, bundle } = useSession();
  const { openSingletonPanel } = useDock();

  const {
    data: basicInfo,
    isLoading,
    error,
  } = useRpcQuery<BasicInfo>(["appInfo"], (api) => api.info.basics());

  const openFinderTab = (path: string) => {
    openSingletonPanel({
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      params: { path },
    });
  };

  return (
    <div className="h-full p-4 overflow-auto">
      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>{(error as Error)?.message}</AlertDescription>
        </Alert>
      )}
      {isLoading ? (
        <div className="space-y-4">
          <div className="flex gap-4">
            <Skeleton className="h-16 w-16 rounded-xl shrink-0" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-full" />
            </div>
          </div>
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-3/4" />
        </div>
      ) : basicInfo ? (
        <div className="space-y-4 pb-4">
          <div className="flex gap-4">
            <img
              src={`/api/device/${device}/icon/${bundle}`}
              alt={basicInfo.label}
              loading="lazy"
              className="h-16 w-16 rounded-xl shrink-0"
              onError={(e) => {
                e.currentTarget.src =
                  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64'%3E%3Crect width='64' height='64' fill='%23ddd'/%3E%3C/svg%3E";
              }}
            />
            <div className="flex-1 min-w-0">
              <div>
                <div className="text-sm text-muted-foreground mb-1">
                  {t("app_name")}
                </div>
                <div className="text-sm">{basicInfo.label || t("na")}</div>
              </div>
              <div className="mt-2">
                <div className="text-sm text-muted-foreground mb-1">
                  {t("bundle_id")}
                </div>
                <div className="text-sm font-mono break-all">
                  {basicInfo.id || t("na")}
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="text-sm text-muted-foreground mb-1">
              {t("version")}
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span>{basicInfo.version || t("na")}</span>
              <Badge variant="secondary" className="text-xs">
                {basicInfo.semVer || t("na")}
              </Badge>
            </div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">
              {t("min_os")}
            </div>
            <Badge variant="outline">{basicInfo.minOS || t("na")}</Badge>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">
              {t("bundle_path")}
            </div>
            {basicInfo.path ? (
              <div className="flex items-start">
                <PathDisplay
                  path={basicInfo.path}
                  onClick={() => openFinderTab("!")}
                />
                <CopyButton text={basicInfo.path} />
              </div>
            ) : (
              <span className="text-sm">{t("na")}</span>
            )}
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">
              {t("executable")}
            </div>
            <div className="flex items-center text-sm font-mono break-all">
              <span className="text-xs">{basicInfo.main || t("na")}</span>
              {basicInfo.main && <CopyButton text={basicInfo.main} />}
            </div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">
              {t("tmp_dir")}
            </div>
            <div className="flex items-center text-sm font-mono break-all">
              <span className="text-xs">{basicInfo.tmp || t("na")}</span>
              {basicInfo.tmp && <CopyButton text={basicInfo.tmp} />}
            </div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">
              {t("home_dir")}
            </div>
            {basicInfo.home ? (
              <div className="flex items-start">
                <PathDisplay
                  path={basicInfo.home}
                  onClick={() => openFinderTab("~")}
                />
                <CopyButton text={basicInfo.home} />
              </div>
            ) : (
              <span className="text-sm">{t("na")}</span>
            )}
          </div>
        </div>
      ) : status === Status.Ready ? (
        <div className="text-sm text-muted-foreground">
          {t("no_app_info")}
        </div>
      ) : (
        <div className="text-sm text-muted-foreground">
          {t("connect_to_view_app_info")}
        </div>
      )}
    </div>
  );
}
