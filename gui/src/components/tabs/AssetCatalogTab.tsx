import { useState, useMemo, useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import {
  RefreshCw,
  Search,
  Image,
  ZoomIn,
  ZoomOut,
  Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useFruityQuery, useFruityMutation } from "@/lib/queries";

import type {
  AssetCatalogInfo,
  AssetVariant,
  AssetImageResult,
  AssetRawResult,
} from "@agent/fruity/modules/assetcatalog";

export interface AssetCatalogTabParams {
  path: string;
}

function VariantLabel({ v }: { v: AssetVariant }) {
  const parts: string[] = [];
  if (v.width && v.height) parts.push(`${v.width}x${v.height}`);
  parts.push(`@${v.scale}x`);
  if (v.isVector) parts.push("vec");
  if (v.isTemplate) parts.push("tpl");
  if (v.uti) parts.push(v.uti.split(".").pop()!);
  return <span>{parts.join(" / ")}</span>;
}

export function AssetCatalogTab({
  params,
}: IDockviewPanelProps<AssetCatalogTabParams>) {
  const { t } = useTranslation();
  const carPath = params?.path || "default";

  const [search, setSearch] = useState("");
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [zoom, setZoom] = useState(100);

  const {
    data: catalogInfo,
    isLoading: catalogLoading,
    error: catalogError,
    refetch,
  } = useFruityQuery<AssetCatalogInfo>(
    ["assetcatalog", carPath],
    (api) => api.assetcatalog.open(carPath),
    { enabled: !!carPath },
  );

  const { data: variantList, isLoading: variantsLoading } = useFruityQuery<
    AssetVariant[]
  >(
    ["assetcatalog-variants", carPath, selectedName ?? ""],
    (api) => api.assetcatalog.variants(carPath, selectedName!),
    { enabled: !!selectedName && !!carPath },
  );

  // Auto-select first variant when variants load
  useEffect(() => {
    if (variantList && variantList.length > 0 && selectedIndex === null) {
      setSelectedIndex(0);
    }
  }, [variantList, selectedIndex]);

  const {
    data: imageData,
    isLoading: imageLoading,
    error: imageError,
  } = useFruityQuery<AssetImageResult | null>(
    ["assetcatalog-image", carPath, selectedName ?? "", String(selectedIndex)],
    (api) => api.assetcatalog.image(carPath, selectedName!, selectedIndex!),
    { enabled: selectedIndex !== null && !!selectedName && !!carPath },
  );

  const downloadMutation = useFruityMutation<
    AssetRawResult | null,
    { carPath: string; name: string; index: number }
  >((api, { carPath, name, index }) =>
    api.assetcatalog.rawImage(carPath, name, index),
  );

  const handleDownload = useCallback(async () => {
    if (!selectedName || selectedIndex === null || !carPath) return;
    const result = await downloadMutation.mutateAsync({
      carPath,
      name: selectedName,
      index: selectedIndex,
    });
    if (!result) return;

    const binary = atob(result.data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = result.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [carPath, selectedName, selectedIndex, downloadMutation]);

  const filteredNames = useMemo(() => {
    if (!catalogInfo) return [];
    if (!search) return catalogInfo.names;
    const lower = search.toLowerCase();
    return catalogInfo.names.filter((n) => n.toLowerCase().includes(lower));
  }, [catalogInfo, search]);

  const handleSelectName = useCallback((name: string) => {
    setSelectedName(name);
    setSelectedIndex(null);
    setZoom(100);
  }, []);

  const handleSelectVariant = useCallback((index: number) => {
    setSelectedIndex(index);
    setZoom(100);
  }, []);

  if (catalogError) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 text-destructive">
        <span>{(catalogError as Error).message}</span>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-2" />
          {t("retry")}
        </Button>
      </div>
    );
  }

  const selectedVariant =
    selectedIndex !== null ? (variantList?.[selectedIndex] ?? null) : null;

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 p-2 border-b">
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          disabled={catalogLoading}
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          {t("reload")}
        </Button>
        {catalogInfo && (
          <span className="text-sm text-muted-foreground">
            {catalogInfo.names.length} assets
          </span>
        )}
      </div>

      {catalogLoading ? (
        <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
          <Spinner className="w-5 h-5" />
          <span>{t("loading")}...</span>
        </div>
      ) : (
        <div className="flex flex-1 overflow-hidden">
          {/* Left: asset name list */}
          <div className="w-64 shrink-0 flex flex-col border-r">
            <div className="p-2 border-b">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder={t("search")}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-8"
                />
              </div>
              {search && (
                <div className="text-xs text-muted-foreground mt-1">
                  {filteredNames.length} / {catalogInfo?.names.length ?? 0}
                </div>
              )}
            </div>
            <div className="flex-1 overflow-auto">
              {filteredNames.map((name) => (
                <button
                  type="button"
                  key={name}
                  onClick={() => handleSelectName(name)}
                  className={`w-full text-left px-3 py-1.5 text-sm truncate hover:bg-accent transition-colors ${
                    selectedName === name ? "bg-accent font-medium" : ""
                  }`}
                  title={name}
                >
                  <Image className="w-3.5 h-3.5 inline mr-2 text-muted-foreground" />
                  {name}
                </button>
              ))}
              {filteredNames.length === 0 && (
                <div className="flex items-center justify-center h-20 text-sm text-muted-foreground">
                  {search ? t("no_results") : "No assets"}
                </div>
              )}
            </div>
          </div>

          {/* Middle: variant list */}
          <div className="w-48 shrink-0 flex flex-col border-r">
            <div className="px-3 py-2 border-b text-xs font-medium text-muted-foreground">
              Variants
              {variantList && (
                <span className="ml-1">({variantList.length})</span>
              )}
            </div>
            <div className="flex-1 overflow-auto">
              {variantsLoading ? (
                <div className="flex items-center justify-center h-20 text-muted-foreground">
                  <Spinner className="w-4 h-4" />
                </div>
              ) : !selectedName ? (
                <div className="flex items-center justify-center h-20 text-xs text-muted-foreground">
                  Select an asset
                </div>
              ) : variantList && variantList.length > 0 ? (
                variantList.map((v) => (
                  <button
                    type="button"
                    key={v.index}
                    onClick={() => handleSelectVariant(v.index)}
                    className={`w-full text-left px-3 py-1.5 text-xs truncate hover:bg-accent transition-colors ${
                      selectedIndex === v.index ? "bg-accent font-medium" : ""
                    }`}
                  >
                    <VariantLabel v={v} />
                  </button>
                ))
              ) : (
                <div className="flex items-center justify-center h-20 text-xs text-muted-foreground">
                  No variants
                </div>
              )}
            </div>
          </div>

          {/* Right: image preview */}
          <div className="flex-1 flex flex-col min-w-0">
            {selectedIndex !== null ? (
              <>
                {/* Image toolbar */}
                <div className="flex items-center gap-2 px-3 py-2 border-b bg-muted/30">
                  <span className="text-sm font-medium truncate">
                    {selectedName}
                  </span>
                  {selectedVariant && (
                    <span className="text-xs text-muted-foreground">
                      @{selectedVariant.scale}x
                    </span>
                  )}
                  <div className="flex items-center gap-1 ml-auto">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={handleDownload}
                      disabled={!imageData || downloadMutation.isPending}
                      title={t("download")}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                    <div className="w-px h-5 bg-border mx-2" />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => setZoom((z) => Math.max(25, z - 25))}
                      disabled={zoom <= 25}
                    >
                      <ZoomOut className="h-4 w-4" />
                    </Button>
                    <span className="text-xs w-10 text-center">{zoom}%</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => setZoom((z) => Math.min(400, z + 25))}
                      disabled={zoom >= 400}
                    >
                      <ZoomIn className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Image display */}
                <div className="flex-1 overflow-auto">
                  {imageLoading ? (
                    <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
                      <Spinner className="w-5 h-5" />
                      <span>{t("loading")}...</span>
                    </div>
                  ) : imageError ? (
                    <div className="flex items-center justify-center h-full text-destructive">
                      {(imageError as Error).message}
                    </div>
                  ) : imageData ? (
                    <div className="p-4">
                      <div className="text-xs text-muted-foreground mb-3 flex gap-4">
                        <span>
                          {imageData.width} x {imageData.height} px
                        </span>
                      </div>
                      <div className="flex items-center justify-center bg-[repeating-conic-gradient(#80808020_0%_25%,transparent_0%_50%)] bg-size-[16px_16px] rounded border p-4">
                        <img
                          src={`data:image/png;base64,${imageData.png}`}
                          alt={selectedName ?? ""}
                          style={{
                            transform: `scale(${zoom / 100})`,
                            transformOrigin: "center",
                            imageRendering: zoom > 200 ? "pixelated" : "auto",
                          }}
                          className="max-w-none transition-transform duration-75"
                        />
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center h-full text-muted-foreground">
                      No image available
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                {selectedName
                  ? "Select a variant to preview"
                  : "Select an asset to preview"}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
