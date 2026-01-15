import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Check, FileText, FolderOpen } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";

import type { BasicInfo } from "../../../../agent/types/fruity/modules/info";
import { Link } from "react-router";

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
      className="ml-2 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
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

export function GeneralPanel() {
  const { t } = useTranslation();
  const { api, status, device, bundle } = useSession();
  const { openSingletonPanel } = useDock();
  const [basicInfo, setBasicInfo] = useState<BasicInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const openHandlesTab = () => {
    openSingletonPanel({
      id: "handles_tab",
      component: "handles",
      title: t("active_file_handles"),
    });
  };

  const openInfoPlistTab = () => {
    openSingletonPanel({
      id: "info_plist_tab",
      component: "infoPlist",
      title: "Info.plist",
    });
  };

  useEffect(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    setIsLoading(true);
    setError(null);
    api.info
      .basics()
      .then((info) => setBasicInfo(info))
      .catch((error) => {
        setError(error?.message);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, [status, api]);

  return (
    <div className="h-full p-4 overflow-auto">
      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
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
        <div className="space-y-4">
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
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                  {t("app_name")}
                </div>
                <div className="text-sm">{basicInfo.label || t("na")}</div>
              </div>
              <div className="mt-2">
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                  {t("bundle_id")}
                </div>
                <div className="text-sm font-mono break-all">
                  {basicInfo.id || t("na")}
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
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
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("min_os")}
            </div>
            <Badge variant="outline">{basicInfo.minOS || t("na")}</Badge>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("bundle_path")}
            </div>
            <div className="flex items-center text-sm font-mono break-all">
              <span>{basicInfo.path || t("na")}</span>
              {basicInfo.path && <CopyButton text={basicInfo.path} />}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("executable")}
            </div>
            <div className="flex items-center text-sm font-mono break-all">
              <span>{basicInfo.main || t("na")}</span>
              {basicInfo.main && <CopyButton text={basicInfo.main} />}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("tmp_dir")}
            </div>
            <div className="flex items-center text-sm font-mono break-all">
              <span>{basicInfo.tmp || t("na")}</span>
              {basicInfo.tmp && <CopyButton text={basicInfo.tmp} />}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("home_dir")}
            </div>
            <div className="flex items-center text-sm font-mono break-all">
              <Link
                to={`/workspace/${device}/${bundle}/files`}
                className="hover:underline"
              >
                <span>{basicInfo.home || t("na")}</span>
              </Link>
              {basicInfo.home && <CopyButton text={basicInfo.home} />}
            </div>
          </div>
          <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={openHandlesTab}>
                <FolderOpen className="w-4 h-4 mr-2" />
                {t("active_file_handles")}
              </Button>
              <Button variant="outline" size="sm" onClick={openInfoPlistTab}>
                <FileText className="w-4 h-4 mr-2" />
                Info.plist
              </Button>
            </div>
          </div>
        </div>
      ) : status === ConnectionStatus.Ready ? (
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {t("no_app_info")}
        </div>
      ) : (
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {t("connect_to_view_app_info")}
        </div>
      )}
    </div>
  );
}
