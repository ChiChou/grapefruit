import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

export type Stride = 8 | 16 | 32 | 64;

interface HexViewParams {
  data: Uint8Array;
  stride: Stride;
}

export default function HexView({ data, stride }: HexViewParams) {
  const count = Math.ceil(data.byteLength / stride);
  const scrollRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 24,
  });

  return (
    <div ref={scrollRef} className="h-full overflow-auto">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((vItem) => {
          const start = vItem.index * stride;
          const end = Math.min(start + stride);
          const chunk = Array.from(data.slice(start, end));
          const offset = start.toString(16).padStart(8, "0");
          const w = stride * 3 - 1;
          const xxd = chunk.map((val) => val.toString(16).padStart(2, "0"));
          const hexColumn = xxd.join(" ").padEnd(w, " ");
          const ascii = chunk.map(printable).join("");

          return (
            <div
              key={vItem.key}
              className="absolute left-0 right-0 flex items-start leading-6 text-sm gap-4"
              style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
            >
              <code className="text-green-500">{offset}</code>
              <code className="whitespace-pre">{hexColumn}</code>
              <code className="whitespace-pre">{ascii}</code>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function printable(value: number) {
  return value >= 32 && value <= 126 ? String.fromCharCode(value) : ".";
}
