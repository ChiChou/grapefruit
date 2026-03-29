import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { Upload, FileCode, FolderOpen, Loader2 } from "lucide-react";

import logo from "../../assets/logo.svg";
import { DarkmodeToggle } from "../shared/DarkmodeToggle";
import { LanguageSelector } from "../shared/LanguageSelector";
import { Button } from "@/components/ui/button";
import { useHBC } from "@/lib/use-hbc";
import { HermesViewer } from "@/components/shared/HermesViewer";

export function HermesPage() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const [buffer, setBuffer] = useState<ArrayBuffer | null>(null);
  const [filename, setFilename] = useState("hermes");
  const hbc = useHBC(buffer);

  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    const source = searchParams.get("source");
    if (source !== "download") return;
    const device = searchParams.get("device");
    const identifier = searchParams.get("identifier");
    const id = searchParams.get("id");
    const name = searchParams.get("name");
    if (!device || !identifier || !id) return;
    if (name) setFilename(name);

    (async () => {
      try {
        const res = await fetch(
          `/api/hermes/${device}/${identifier}/download/${id}`,
        );
        if (!res.ok) return;
        setBuffer(await res.arrayBuffer());
      } catch {
        /* ignore */
      }
    })();
  }, [searchParams]);

  const loadFile = useCallback((file: File) => {
    setFilename(file.name);
    file.arrayBuffer().then((buf) => setBuffer(buf));
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) loadFile(file);
    },
    [loadFile],
  );

  const onFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) loadFile(file);
    },
    [loadFile],
  );

  const openFile = useCallback(() => {
    inputRef.current?.click();
  }, []);

  return (
    <div className="h-screen w-screen flex flex-col">
      <div className="flex items-center gap-2 px-3 py-1 border-b shrink-0 bg-sidebar">
        <Link to="/" className="shrink-0">
          <img src={logo} alt="IGF" className="h-5 w-20" />
        </Link>
        <div className="w-px h-4 bg-border mx-1" />
        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={openFile}>
          <FolderOpen className="h-3.5 w-3.5 mr-1" />
          {t("open")}
        </Button>
        <div className="flex-1 flex items-center justify-center">
          <span className="text-xs text-muted-foreground">
            {t("hermes_decompiler")}
          </span>
        </div>
        <DarkmodeToggle />
        <LanguageSelector />
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".hbc,.jsbundle"
        className="hidden"
        onChange={onFileChange}
      />

      {hbc.data ? (
        <div className="flex-1 overflow-hidden">
          <HermesViewer
            data={hbc.data}
            xrefs={hbc.xrefs}
            filename={filename}
            buffer={hbc.buffer}
            disassemble={hbc.disassemble}
            decompile={hbc.decompile}
          />
        </div>
      ) : (
        <div
          className={`flex-1 flex items-center justify-center transition-colors ${
            dragging ? "bg-primary/5" : ""
          }`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <div className="flex flex-col items-center gap-4 max-w-sm text-center">
            {hbc.isLoading ? (
              <>
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  {t("hermes_parsing")}
                </p>
              </>
            ) : (
              <>
                {dragging ? (
                  <FileCode className="h-12 w-12 text-primary" />
                ) : (
                  <Upload className="h-12 w-12 text-muted-foreground/40" />
                )}
                <div>
                  <p className="text-sm font-medium">
                    {dragging ? t("hermes_drop_to_analyze") : t("hermes_drop_file")}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {t("hermes_file_types")}
                  </p>
                </div>
                {hbc.error && (
                  <p className="text-xs text-destructive">{hbc.error}</p>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
