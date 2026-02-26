import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search, Send, Eraser, UnlinkIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import { Textarea } from "@/components/ui/textarea";
import {
  ResizablePanel,
  ResizablePanelGroup,
  ResizableHandle,
} from "@/components/ui/resizable";

import { useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { useDroidQuery, useDroidMutation } from "@/lib/queries";

interface DroidURLScheme {
  activity: string;
  schemes: string[];
  hosts: string[];
  browsable: boolean;
  actions: string[];
}

function parseManifestSchemes(xml: string): DroidURLScheme[] {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, "text/xml");

  if (doc.documentElement.tagName === "parsererror") {
    return [];
  }

  const result: DroidURLScheme[] = [];

  const activities = doc.querySelectorAll("activity, activity-alias");

  for (const activity of activities) {
    const activityName = activity.getAttribute("name") || "";
    const filters = activity.querySelectorAll("intent-filter");

    for (const filter of filters) {
      const dataEls = filter.querySelectorAll("data");
      const schemes: string[] = [];
      const hosts: string[] = [];

      for (const data of dataEls) {
        const scheme = data.getAttribute("scheme");
        if (scheme) schemes.push(scheme);
        const host = data.getAttribute("host");
        if (host) hosts.push(host);
      }

      if (schemes.length === 0) continue;

      const actions: string[] = [];
      for (const action of filter.querySelectorAll("action")) {
        const name = action.getAttribute("name");
        if (name) actions.push(name);
      }

      let browsable = false;
      for (const category of filter.querySelectorAll("category")) {
        if (
          category.getAttribute("name") ===
          "android.intent.category.BROWSABLE"
        ) {
          browsable = true;
          break;
        }
      }

      result.push({
        activity: activityName,
        schemes: [...new Set(schemes)],
        hosts: [...new Set(hosts)],
        browsable,
        actions,
      });
    }
  }

  return result;
}

function shortName(fullName: string): string {
  const idx = fullName.lastIndexOf(".");
  return idx >= 0 ? fullName.substring(idx + 1) : fullName;
}

function DroidURLSendView({ scheme }: { scheme: string }) {
  const { t } = useTranslation();
  const { droid } = useSession();
  const [url, setURL] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const launchMutation = useDroidMutation<void, { data: string }>(
    (api, { data }) =>
      api.activities.start({
        action: "android.intent.action.VIEW",
        data,
      }),
  );

  useEffect(() => {
    setURL(scheme + "://");
    textareaRef.current?.focus();
  }, [scheme]);

  const handleSend = async () => {
    if (isLoading || !droid) return;
    setError(null);
    setIsLoading(true);
    try {
      await launchMutation.mutateAsync({ data: url });
    } catch (e) {
      setError(`${e}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      handleSend();
    }
  };

  const reset = () => {
    if (isLoading) return;
    setURL(scheme + "://");
    textareaRef.current?.focus();
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex flex-col flex-1 p-2 gap-2">
        <Textarea
          ref={textareaRef}
          value={url}
          onChange={(e) => setURL(e.target.value)}
          onKeyDown={handleKeyDown}
          className="font-mono resize-none flex-1 min-h-0"
          placeholder={t("enter_url_scheme")}
          readOnly={isLoading}
        />
        <div className="flex justify-end shrink-0">
          <div className="inline-flex items-center gap-2">
            {error && (
              <span className="text-sm text-destructive">{error}</span>
            )}
            <ButtonGroup>
              <Button
                size="sm"
                onClick={reset}
                variant="outline"
                disabled={isLoading}
                title={t("reset")}
                className="px-2"
              >
                <Eraser className="size-4" />
              </Button>
              <Button
                size="sm"
                onClick={handleSend}
                className="gap-2"
                variant="outline"
                disabled={isLoading}
              >
                <Send className="size-4" />
                {t("send")}
              </Button>
            </ButtonGroup>
          </div>
        </div>
      </div>
    </div>
  );
}

export function DroidURLSchemesPanel() {
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedScheme, setSelectedScheme] = useState<string | null>(null);

  const openManifest = () => {
    openSingletonPanel({
      id: "droid_manifest_tab",
      component: "droidManifest",
      title: "AndroidManifest.xml",
    });
  };

  const {
    data: manifestXml,
    isLoading,
    error,
    refetch,
  } = useDroidQuery(["manifest"], (api) => api.manifest.xml());

  const allSchemes = useMemo(() => {
    if (!manifestXml) return [];
    return parseManifestSchemes(manifestXml);
  }, [manifestXml]);

  const filteredSchemes = useMemo(() => {
    if (!searchQuery.trim()) return allSchemes;
    const query = searchQuery.toLowerCase();
    return allSchemes.filter(
      (entry) =>
        entry.activity.toLowerCase().includes(query) ||
        entry.schemes.some((s) => s.toLowerCase().includes(query)) ||
        entry.hosts.some((h) => h.toLowerCase().includes(query)),
    );
  }, [searchQuery, allSchemes]);

  const schemeList = (
    <>
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
        <div className="space-y-4">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ) : filteredSchemes.length > 0 ? (
        <div className="space-y-4">
          {filteredSchemes.map((entry, index) => (
            <div key={index} className="rounded-lg p-2">
              <div className="flex items-center justify-between gap-2 mb-1">
                <span
                  className="text-xs truncate"
                  title={entry.activity}
                >
                  {shortName(entry.activity)}
                </span>
                <div className="flex items-center gap-1 shrink-0">
                  {entry.browsable && (
                    <Badge className="text-xs bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                      BROWSABLE
                    </Badge>
                  )}
                  {entry.actions.includes("android.intent.action.VIEW") && (
                    <Badge variant="outline" className="text-xs">
                      VIEW
                    </Badge>
                  )}
                </div>
              </div>
              <div className="text-xs text-muted-foreground font-mono mb-1 truncate">
                {entry.activity}
              </div>
              {entry.hosts.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-1 ml-1">
                  {entry.hosts.map((h, i) => (
                    <Badge
                      key={i}
                      variant="secondary"
                      className="text-xs font-mono"
                    >
                      {h}
                    </Badge>
                  ))}
                </div>
              )}
              <div className="space-y-1 ml-1">
                {entry.schemes.map((s, i) => (
                  <button
                    key={i}
                    type="button"
                    className="w-full cursor-pointer text-left font-mono text-sm text-amber-600 dark:text-amber-400 rounded-sm px-1 py-0.5 transition-colors hover:underline"
                    onClick={() => setSelectedScheme(s)}
                  >
                    {s}://
                    {entry.hosts.length > 0 ? entry.hosts[0] : ""}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center gap-2 p-8 text-center text-muted-foreground h-full">
          <UnlinkIcon className="size-8" />
          <span className="text-sm">
            {searchQuery.trim()
              ? t("no_results")
              : t("no_url_schemes")}
          </span>
          {!searchQuery.trim() && (
            <>
              <Button
                variant="link"
                size="sm"
                className="text-xs"
                onClick={() => refetch()}
              >
                {t("reload")}
              </Button>
              <Button
                variant="link"
                size="sm"
                className="text-xs"
                onClick={openManifest}
              >
                {t("open_manifest")}
              </Button>
            </>
          )}
        </div>
      )}
    </>
  );

  return (
    <div className="h-full flex flex-col">
      {!isLoading && allSchemes.length > 0 && (
        <div className="p-4 pb-2">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t("search")}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8"
            />
          </div>
        </div>
      )}
      {selectedScheme ? (
        <ResizablePanelGroup orientation="vertical" className="flex-1 min-h-0">
          <ResizablePanel defaultSize="60%" minSize="30%">
            <div className="flex-1 overflow-auto p-4 pt-2 h-full">
              {schemeList}
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel minSize="20%" className="border-t">
            <DroidURLSendView scheme={selectedScheme} />
          </ResizablePanel>
        </ResizablePanelGroup>
      ) : (
        <div className="flex-1 overflow-auto p-4 pt-2">
          {schemeList}
        </div>
      )}
    </div>
  );
}
