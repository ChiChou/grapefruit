import { useMemo, useRef, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  parse,
  resolve,
  findJumps,
  type Line,
} from "@/lib/hermes-asm";
import type { HBCFunction, HBCString } from "@/lib/use-hbc";

export interface HermesDisasmProps {
  raw: string;
  strings: HBCString[];
  functions: HBCFunction[];
  showAddresses: boolean;
  onFuncClick?: (funcId: number) => void;
}

const ROW_HEIGHT = 20;
const ARROW_COL_W = 8;
const GUTTER_PAD = 4;
const GUTTER_RIGHT = 8;
const LEFT_PAD = 12;

const ARROW_COLORS = [
  "#3b82f6", // blue
  "#f59e0b", // amber
  "#10b981", // emerald
  "#ef4444", // red
  "#8b5cf6", // violet
  "#ec4899", // pink
  "#06b6d4", // cyan
  "#f97316", // orange
];

export function HermesDisasm({
  raw,
  strings,
  functions,
  showAddresses,
  onFuncClick,
}: HermesDisasmProps) {
  const parentRef = useRef<HTMLDivElement>(null);

  const { lines, jumps, maxCol, opcodeW, funcByOffset } = useMemo(() => {
    const lines = parse(raw);
    resolve(lines, strings, functions);
    const jumps = findJumps(lines);
    const maxCol = jumps.reduce((m, j) => Math.max(m, j.column), -1) + 1;

    let longest = 0;
    for (const l of lines) {
      if (l.type === "instruction" && l.opcode && l.opcode.length > longest) {
        longest = l.opcode.length;
      }
    }

    const fbo = new Map<number, HBCFunction>();
    for (const f of functions) fbo.set(f.offset, f);

    return { lines, jumps, maxCol, opcodeW: longest, funcByOffset: fbo };
  }, [raw, strings, functions]);

  const gutterW = maxCol > 0 ? maxCol * ARROW_COL_W + GUTTER_PAD * 2 + GUTTER_RIGHT : 0;

  const virtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 40,
  });

  const handleClosureClick = useCallback(
    (offsetStr: string) => {
      if (!onFuncClick) return;
      const offset = parseInt(offsetStr, 16) || parseInt(offsetStr, 10);
      const func = funcByOffset.get(offset);
      if (func) onFuncClick(func.id);
    },
    [onFuncClick, funcByOffset],
  );

  return (
    <div ref={parentRef} className="h-full overflow-auto font-mono text-xs leading-5 select-text">
      <div
        style={{
          height: virtualizer.getTotalSize(),
          position: "relative",
        }}
      >
        {/* Arrow gutter SVG */}
        {gutterW > 0 && (
          <svg
            className="absolute top-0 pointer-events-none"
            style={{ left: LEFT_PAD, width: gutterW, height: virtualizer.getTotalSize() }}
          >
            {jumps.map((j, i) => {
              const fromY = j.from * ROW_HEIGHT + ROW_HEIGHT / 2;
              const toY = j.to * ROW_HEIGHT + ROW_HEIGHT / 2;
              const x = GUTTER_PAD + j.column * ARROW_COL_W + ARROW_COL_W / 2;
              const color = ARROW_COLORS[i % ARROW_COLORS.length];
              const tickR = gutterW - GUTTER_RIGHT;
              return (
                <g key={i} opacity={0.6}>
                  <line
                    x1={x} y1={fromY} x2={x} y2={toY}
                    stroke={color} strokeWidth={1}
                  />
                  <line
                    x1={x} y1={fromY} x2={tickR} y2={fromY}
                    stroke={color} strokeWidth={1}
                  />
                  <line
                    x1={x} y1={toY} x2={tickR} y2={toY}
                    stroke={color} strokeWidth={1}
                  />
                  <polygon
                    points={`${tickR},${toY - 3} ${tickR},${toY + 3} ${tickR + 4},${toY}`}
                    fill={color}
                  />
                </g>
              );
            })}
          </svg>
        )}

        {/* Rows */}
        {virtualizer.getVirtualItems().map((vRow) => {
          const line = lines[vRow.index];
          return (
            <div
              key={vRow.index}
              className="absolute left-0 right-0 flex items-center hover:bg-accent/30 whitespace-nowrap"
              style={{
                height: ROW_HEIGHT,
                transform: `translateY(${vRow.start}px)`,
                paddingLeft: LEFT_PAD + gutterW,
              }}
            >
              <Row
                line={line}
                showAddress={showAddresses}
                opcodeW={opcodeW}
                onClosureClick={handleClosureClick}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Row({
  line,
  showAddress,
  opcodeW,
  onClosureClick,
}: {
  line: Line;
  showAddress: boolean;
  opcodeW: number;
  onClosureClick: (offset: string) => void;
}) {
  if (line.type === "blank") return null;

  if (line.type === "separator") {
    return <span className="text-muted-foreground/40">{line.text}</span>;
  }

  if (line.type === "comment") {
    return <span className="text-muted-foreground italic">{line.text}</span>;
  }

  const isClosure = line.opcode === "create_closure" || line.opcode === "create_closure_long_index";
  const anns = line.annotations;

  // Collect trailing comment parts
  const comments: { text: string; isClosure: boolean; operand: string }[] = [];
  if (anns) {
    for (const [i, text] of anns) {
      comments.push({ text, isClosure: isClosure && i === 2, operand: line.operands![i] });
    }
  }

  return (
    <>
      {showAddress && (
        <span className="text-muted-foreground/50 mr-3 shrink-0 tabular-nums">
          {line.address}
        </span>
      )}
      <span
        className="text-muted-foreground shrink-0 mr-2"
        style={{ width: `${opcodeW}ch`, display: "inline-block" }}
      >
        {line.opcode}
      </span>
      <span className="shrink-0">
        {(line.operands ?? []).map((op, i) => {
          const isLast = i === (line.operands!.length - 1);
          const sep = isLast ? "" : ", ";

          if (op.startsWith("r")) {
            return (
              <span key={i}>
                <span className="text-sky-700 dark:text-cyan-400/80">{op}</span>
                {sep}
              </span>
            );
          }

          return <span key={i}>{op}{sep}</span>;
        })}
      </span>
      {comments.length > 0 && (
        <span className="ml-4 text-muted-foreground">
          {"; "}
          {comments.map((c, i) => (
            <span key={i}>
              {i > 0 && ", "}
              {c.isClosure ? (
                <button
                  className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  onClick={() => onClosureClick(c.operand)}
                >
                  {c.text}
                </button>
              ) : (
                <span className="text-emerald-700 dark:text-green-400/70">{c.text}</span>
              )}
            </span>
          ))}
        </span>
      )}
    </>
  );
}
