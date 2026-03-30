import { useRef, useCallback, type ReactNode } from "react";
import { useVirtualizer, type Virtualizer } from "@tanstack/react-virtual";

export type Stride = 8 | 16 | 32 | 64;

interface BufferProps {
  data: Uint8Array;
  stride: Stride;
  onSelect?: (offset: number) => void;
  selectedOffset?: number;
}

interface PagedProps {
  fileSize: number;
  stride: Stride;
  getBytes: (offset: number, length: number) => Uint8Array | null;
  requestBytes: (offset: number, length: number) => void;
  onSelect?: (offset: number) => void;
  selectedOffset?: number;
  /** Increment externally to re-render when pages load */
  version?: number;
}

export type HexViewProps = BufferProps | PagedProps;

function isPaged(p: HexViewProps): p is PagedProps {
  return "fileSize" in p;
}

export interface HexViewHandle {
  virtualizer: Virtualizer<HTMLDivElement, Element>;
}

export default function HexView(props: HexViewProps & { onReady?: (h: HexViewHandle) => void }) {
  const { stride, onSelect, selectedOffset, onReady } = props;
  const totalSize = isPaged(props) ? props.fileSize : props.data.byteLength;
  const count = Math.ceil(totalSize / stride);
  const scrollRef = useRef<HTMLDivElement>(null);
  const addrWidth = Math.max(8, totalSize.toString(16).length);
  const hexW = stride * 3 - 1;

  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 24,
  });

  const readyRef = useRef(false);
  if (!readyRef.current && onReady) {
    readyRef.current = true;
    onReady({ virtualizer });
  }

  const getRow = useCallback(
    (index: number): Uint8Array | null => {
      const start = index * stride;
      const len = Math.min(stride, totalSize - start);
      if (isPaged(props)) {
        const bytes = props.getBytes(start, len);
        if (!bytes) {
          props.requestBytes(start, len);
          return null;
        }
        return bytes;
      }
      return props.data.subarray(start, start + len);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [stride, totalSize, isPaged(props) ? (props as PagedProps).version : props.data],
  );

  return (
    <div ref={scrollRef} className="h-full overflow-auto font-mono text-sm [&::-webkit-scrollbar]:w-16 [&::-webkit-scrollbar-track]:bg-muted/30 [&::-webkit-scrollbar-thumb]:rounded-none [&::-webkit-scrollbar-thumb]:bg-muted-foreground/30 [&::-webkit-scrollbar-thumb]:bg-clip-content [&::-webkit-scrollbar-thumb]:border-y-[calc(50%-1px)] [&::-webkit-scrollbar-thumb]:border-transparent [&::-webkit-scrollbar-thumb:hover]:bg-muted-foreground/50">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((vItem) => {
            const chunk = getRow(vItem.index);
            const start = vItem.index * stride;
            const addr = start.toString(16).padStart(addrWidth, "0");

            if (!chunk) {
              return (
                <div
                  key={vItem.key}
                  className="absolute left-0 right-0 flex items-start leading-6 gap-4 px-2"
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
                >
                  <code className="text-green-500 select-none">{addr}</code>
                  <code className="text-muted-foreground/40 whitespace-pre">
                    {"·· ".repeat(stride).trimEnd().padEnd(hexW)}
                  </code>
                </div>
              );
            }

            const bytes = Array.from(chunk);
            const hexParts: ReactNode[] = [];
            const asciiParts: ReactNode[] = [];

            for (let i = 0; i < bytes.length; i++) {
              const abs = start + i;
              const sel = selectedOffset === abs;
              const cls = sel ? "bg-accent text-accent-foreground rounded-sm" : "";
              const click = onSelect ? () => onSelect(abs) : undefined;
              const cur = onSelect ? "pointer" : undefined;

              hexParts.push(
                <span key={i} className={cls} onClick={click} style={{ cursor: cur }}>
                  {bytes[i].toString(16).padStart(2, "0")}
                </span>,
              );
              if (i < bytes.length - 1) hexParts.push(" ");

              const ch = bytes[i] >= 32 && bytes[i] <= 126 ? String.fromCharCode(bytes[i]) : ".";
              asciiParts.push(
                <span key={i} className={cls} onClick={click} style={{ cursor: cur }}>
                  {ch}
                </span>,
              );
            }

            return (
              <div
                key={vItem.key}
                className="absolute left-0 right-0 flex items-start leading-6 gap-4 px-2"
                style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
              >
                <code className="text-green-500 select-none">{addr}</code>
                <code className="whitespace-pre">{hexParts}</code>
                <code className="whitespace-pre">{asciiParts}</code>
              </div>
            );
          })}
      </div>
    </div>
  );
}

