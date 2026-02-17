import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import {
  ResizablePanel,
  ResizablePanelGroup,
  ResizableHandle,
} from "@/components/ui/resizable";

import { URLSendView } from "@/components/URLSendView";
import { useRpcQuery } from "@/lib/queries";

import type { URLScheme } from "@agent/fruity/modules/info";

export function URLSchemesPanel() {
  const { t } = useTranslation();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedScheme, setSelectedScheme] = useState<string | null>(null);

  const {
    data: urlSchemes,
    isLoading,
    error,
  } = useRpcQuery(["urlSchemes"], (api) => api.info.urls());

  const [filteredSchemes, setFilteredSchemes] = useState<URLScheme[] | null>(
    null,
  );

  useEffect(() => {
    if (!urlSchemes) {
      setFilteredSchemes(null);
      return;
    }

    if (!searchQuery.trim()) {
      setFilteredSchemes(urlSchemes);
      return;
    }

    const query = searchQuery.toLowerCase();
    const filtered = urlSchemes.filter(
      (scheme) =>
        scheme.name?.toLowerCase().includes(query) ||
        scheme.schemes?.some((s) => s.toLowerCase().includes(query)),
    );
    setFilteredSchemes(filtered);
  }, [searchQuery, urlSchemes]);

  const schemeList = (
    <>
      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>
            {(error as Error)?.message}
          </AlertDescription>
        </Alert>
      )}
      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ) : filteredSchemes && filteredSchemes.length > 0 ? (
        <div className="space-y-4">
          {filteredSchemes.map((scheme: URLScheme, index: number) => (
            <div key={index} className="rounded-lg p-2">
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="text-xs">
                  {scheme.name || "(empty)"}
                </span>
                <Badge variant="outline" className="text-xs shrink-0">
                  {scheme.role}
                </Badge>
              </div>
              <div className="space-y-1 ml-1">
                {scheme.schemes?.map((s, i) => (
                  <button
                    key={i}
                    type="button"
                    className="w-full cursor-pointer text-left font-mono text-sm text-amber-600 dark:text-amber-400 rounded-sm px-1 py-0.5 transition-colors hover:underline"
                    onClick={() => s && setSelectedScheme(s)}
                  >
                    {s}://
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      )}
    </>
  );

  return (
    <div className="h-full flex flex-col">
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
      {selectedScheme ? (
        <ResizablePanelGroup orientation="vertical" className="flex-1 min-h-0">
          <ResizablePanel defaultSize="60%" minSize="30%">
            <div className="flex-1 overflow-auto p-4 pt-2 h-full">
              {schemeList}
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel minSize="20%" className="border-t">
            <URLSendView scheme={selectedScheme} />
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
