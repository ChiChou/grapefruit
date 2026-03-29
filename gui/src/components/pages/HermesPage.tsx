import { useCallback, useRef, useState } from "react";
import { Link } from "react-router";
import { Upload, FileCode } from "lucide-react";

import logo from "../../assets/logo.svg";
import { DarkmodeToggle } from "../shared/DarkmodeToggle";
import { useHBC } from "@/lib/use-hbc";
import { HermesViewer } from "@/components/shared/HermesViewer";
import { Loader2 } from "lucide-react";

export function HermesPage() {
  const [buffer, setBuffer] = useState<ArrayBuffer | null>(null);
  const [filename, setFilename] = useState("hermes");
  const { data, xrefs, isLoading, error, disassemble, decompile } =
    useHBC(buffer);

  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

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

  // Show viewer once loaded
  if (data) {
    return (
      <div className="h-screen w-screen flex flex-col">
        <div className="flex items-center gap-3 px-4 py-1.5 border-b shrink-0 bg-sidebar">
          <Link to="/">
            <img src={logo} alt="IGF" className="h-6 w-24" />
          </Link>
          <span className="text-xs text-muted-foreground">/</span>
          <span className="text-xs font-medium">Hermes Disassembler</span>
          <button
            className="ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
            onClick={() => {
              setBuffer(null);
              setFilename("hermes");
            }}
          >
            Open another file
          </button>
          <DarkmodeToggle />
        </div>
        <div className="flex-1 overflow-hidden">
          <HermesViewer
            data={data}
            xrefs={xrefs}
            filename={filename}
            disassemble={disassemble}
            decompile={decompile}
          />
        </div>
      </div>
    );
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Parsing Hermes bytecode...
      </div>
    );
  }

  // Upload UI
  return (
    <div className="flex items-center justify-center h-screen">
      <div className="flex flex-col items-center gap-6 max-w-lg w-full px-6">
        <Link to="/">
          <img src={logo} alt="IGF" className="h-10 w-40" />
        </Link>
        <h1 className="text-lg font-semibold">Hermes Bytecode Disassembler</h1>
        <p className="text-sm text-muted-foreground text-center">
          Analyze React Native Hermes bytecode directly in your browser.
          No server required.
        </p>

        <div
          className={`w-full border-2 border-dashed rounded-lg p-12 text-center transition-colors cursor-pointer ${
            dragging
              ? "border-primary bg-primary/5"
              : "border-muted-foreground/25 hover:border-muted-foreground/50"
          }`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".hbc,.jsbundle"
            className="hidden"
            onChange={onFileChange}
          />
          <div className="flex flex-col items-center gap-3">
            {dragging ? (
              <FileCode className="h-10 w-10 text-primary" />
            ) : (
              <Upload className="h-10 w-10 text-muted-foreground" />
            )}
            <div className="text-sm">
              {dragging ? (
                <span className="text-primary font-medium">Drop to analyze</span>
              ) : (
                <>
                  <span className="font-medium">Click to upload</span>
                  <span className="text-muted-foreground"> or drag and drop</span>
                </>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              .hbc or .jsbundle files
            </p>
          </div>
        </div>

        {error && (
          <div className="text-sm text-destructive text-center">{error}</div>
        )}

        <div className="flex items-center gap-2 mt-2">
          <DarkmodeToggle />
        </div>
      </div>
    </div>
  );
}
