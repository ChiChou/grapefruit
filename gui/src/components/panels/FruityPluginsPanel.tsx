import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search, Copy, Check, PackageOpen } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

import { useFruityQuery } from "@/lib/queries";

import type { PluginInfo } from "@agent/fruity/modules/plugins";

function CopyableText({ text, hideText }: { text: string; hideText?: boolean }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span className="inline-flex items-center gap-1 font-mono text-sm break-all">
      {!hideText && text}
      <button
        type="button"
        onClick={handleCopy}
        className="p-0.5 text-muted-foreground hover:text-foreground shrink-0"
      >
        {copied ? (
          <Check className="w-3 h-3 text-green-500" />
        ) : (
          <Copy className="w-3 h-3" />
        )}
      </button>
    </span>
  );
}

export function FruityPluginsPanel() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");

  const {
    data: plugins,
    isLoading,
    error,
    refetch,
  } = useFruityQuery<PluginInfo[]>(["plugins"], (api) => api.plugins.list());

  const filtered = useMemo(() => {
    if (!plugins) return [];
    if (!search.trim()) return plugins;
    const q = search.toLowerCase();
    return plugins.filter(
      (p) =>
        p.identifier.toLowerCase().includes(q) ||
        p.extensionPoint.toLowerCase().includes(q) ||
        p.displayName.toLowerCase().includes(q),
    );
  }, [plugins, search]);

  return (
    <div className="h-full flex flex-col">
      {!isLoading && !error && plugins && plugins.length > 0 && (
        <div className="p-4 pb-2 space-y-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t("search")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <div className="text-sm text-muted-foreground">
            {filtered.length} / {plugins.length}
          </div>
        </div>
      )}
      <div className="flex-1 min-h-0 overflow-auto">
        {error ? (
          <div className="flex flex-col items-center justify-center gap-2 p-8 text-center h-full">
            <Alert variant="destructive">
              <AlertTitle>{t("error")}</AlertTitle>
              <AlertDescription>{(error as Error)?.message}</AlertDescription>
            </Alert>
            <Button
              variant="link"
              size="sm"
              className="text-xs"
              onClick={() => refetch()}
            >
              {t("reload")}
            </Button>
          </div>
        ) : isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
            {t("loading")}...
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 text-muted-foreground">
            <PackageOpen className="size-8" />
            <span className="text-sm">
              {search.trim()
                ? t("no_results")
                : t("no_extensions")}
            </span>
            {!search.trim() && (
              <Button
                variant="link"
                size="sm"
                className="text-xs"
                onClick={() => refetch()}
              >
                {t("reload")}
              </Button>
            )}
          </div>
        ) : (
          <div className="divide-y divide-border">
            {filtered.map((plugin) => (
              <div
                key={plugin.identifier}
                className="px-4 py-3 hover:bg-accent space-y-1.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium truncate">
                    {plugin.displayName !== "N/A"
                      ? plugin.displayName
                      : plugin.identifier.split(".").pop()}
                  </span>
                  <Badge variant="secondary" className="text-xs shrink-0">
                    {plugin.extensionPoint}
                  </Badge>
                </div>
                <div className="space-y-0.5">
                  <CopyableText text={plugin.identifier} />
                </div>
                {plugin.path !== "N/A" && (
                  <div className="flex items-center gap-1 min-w-0">
                    <div
                      dir="rtl"
                      className="text-xs text-muted-foreground font-mono truncate"
                    >
                      <bdi>{plugin.path}</bdi>
                    </div>
                    <CopyableText text={plugin.path} hideText />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
