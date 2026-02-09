import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Check } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import { Status, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { useDroidRpcQuery } from "@/lib/queries";

import type { ApplicationInfoResult } from "@agent/droid/modules/app";


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

function DownloadLink({ path, href }: { path: string; href: string }) {
  return (
    <a
      href={href}
      download
      className="text-left text-sm font-mono break-all hover:text-amber-600 dark:hover:text-amber-400 transition-colors hover:underline"
    >
      <span className="text-xs">{path}</span>
    </a>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mt-4 mb-2">
      {children}
    </div>
  );
}

function InfoRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      {children}
    </div>
  );
}

export function DroidGeneralPanel() {
  const { t } = useTranslation();
  const { status, device, bundle, pid } = useSession();
  const { openSingletonPanel } = useDock();

  const {
    data: appInfo,
    isLoading,
    error,
  } = useDroidRpcQuery<ApplicationInfoResult>(["appInfo"], (api) => api.app.info());

  const openFinderTab = (path: string) => {
    openSingletonPanel({
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      params: { path },
    });
  };

  const downloadUrl = (path: string) =>
    `/api/download/${device}/${pid}?path=${encodeURIComponent(path)}`;

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
      ) : appInfo ? (
        <div className="space-y-3 pb-4">
          <div className="flex gap-4">
            <img
              src={`/api/device/${device}/icon/${bundle}`}
              alt={appInfo.packageName}
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
                  {t("package_name")}
                </div>
                <div className="text-sm font-mono break-all">
                  {appInfo.packageName}
                </div>
              </div>
            </div>
          </div>

          <InfoRow label={t("process_name")}>
            <div className="text-sm font-mono break-all">{appInfo.processName}</div>
          </InfoRow>

          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="secondary" className="text-xs">
              {t("uid")}: {appInfo.uid}
            </Badge>
            <Badge variant="secondary" className="text-xs">
              {t("target_sdk")}: {appInfo.targetSdkVersion}
            </Badge>
            <Badge variant="secondary" className="text-xs">
              {t("min_sdk")}: {appInfo.minSdkVersion}
            </Badge>
          </div>

          <SectionLabel>{t("directories")}</SectionLabel>

          <InfoRow label={t("data_dir")}>
            <div className="flex items-start">
              <PathDisplay path={appInfo.dataDir} onClick={() => openFinderTab(appInfo.dataDir)} />
              <CopyButton text={appInfo.dataDir} />
            </div>
          </InfoRow>

          {appInfo.deviceProtectedDataDir && (
            <InfoRow label={t("data_dir") + " (DE)"}>
              <div className="flex items-center text-sm font-mono break-all">
                <span className="text-xs">{appInfo.deviceProtectedDataDir}</span>
                <CopyButton text={appInfo.deviceProtectedDataDir} />
              </div>
            </InfoRow>
          )}

          <InfoRow label={t("native_library_dir")}>
            <div className="flex items-center text-sm font-mono break-all">
              <span className="text-xs">{appInfo.nativeLibraryDir}</span>
              <CopyButton text={appInfo.nativeLibraryDir} />
            </div>
          </InfoRow>

          <InfoRow label={t("public_source_dir")}>
            <div className="flex items-center text-sm font-mono break-all">
              <span className="text-xs">{appInfo.publicSourceDir}</span>
              <CopyButton text={appInfo.publicSourceDir} />
            </div>
          </InfoRow>

          <InfoRow label={t("source_dir")}>
            <div className="flex items-center text-sm font-mono break-all">
              <span className="text-xs">{appInfo.sourceDir}</span>
              <CopyButton text={appInfo.sourceDir} />
            </div>
          </InfoRow>

          {appInfo.splitPublicSourceDirs && appInfo.splitPublicSourceDirs.length > 0 && (
            <InfoRow label={t("split_apks")}>
              <div className="space-y-1">
                {appInfo.splitPublicSourceDirs.map((p) => (
                  <div key={p} className="flex items-center">
                    <DownloadLink path={p} href={downloadUrl(p)} />
                    <CopyButton text={p} />
                  </div>
                ))}
              </div>
            </InfoRow>
          )}

          {appInfo.sharedLibraryFiles && appInfo.sharedLibraryFiles.length > 0 && (
            <InfoRow label={t("shared_library_files")}>
              <div className="space-y-1">
                {appInfo.sharedLibraryFiles.map((p) => (
                  <div key={p} className="flex items-center">
                    <DownloadLink path={p} href={downloadUrl(p)} />
                    <CopyButton text={p} />
                  </div>
                ))}
              </div>
            </InfoRow>
          )}
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
