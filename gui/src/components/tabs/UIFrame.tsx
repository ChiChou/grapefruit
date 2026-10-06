import { useEffect, useRef, useState } from "react";
import type { PointerEvent, KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";
import { Move } from "lucide-react";
import { shift } from "@/lib/frame";
import type { Box, Edge } from "@/lib/frame";

const edges: { edge: Edge; name: string; cursor: string }[] = [
  { edge: { x: -1, y: -1 }, name: "top_left", cursor: "nwse-resize" },
  { edge: { x: 0, y: -1 }, name: "top", cursor: "ns-resize" },
  { edge: { x: 1, y: -1 }, name: "top_right", cursor: "nesw-resize" },
  { edge: { x: 1, y: 0 }, name: "right", cursor: "ew-resize" },
  { edge: { x: 1, y: 1 }, name: "bottom_right", cursor: "nwse-resize" },
  { edge: { x: 0, y: 1 }, name: "bottom", cursor: "ns-resize" },
  { edge: { x: -1, y: 1 }, name: "bottom_left", cursor: "nesw-resize" },
  { edge: { x: -1, y: 0 }, name: "left", cursor: "ew-resize" },
];

export function UIFrame({ value, original, parent, disabled, onChange }: {
  value: Box;
  original: Box;
  parent: [number, number];
  disabled: boolean;
  onChange: (box: Box) => void;
}) {
  const { t } = useTranslation();
  const host = useRef<HTMLDivElement>(null);
  const gesture = useRef<{ id: number; x: number; y: number; box: Box; scale: number; edge?: Edge } | null>(null);
  const [width, setWidth] = useState(300);
  useEffect(() => {
    if (!host.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(host.current);
    return () => observer.disconnect();
  }, []);
  useEffect(() => { if (disabled) gesture.current = null; }, [disabled]);
  // Keep the coordinate mapping stable throughout a drag.
  const left = Math.min(0, original[0]);
  const top = Math.min(0, original[1]);
  const right = Math.max(parent[0], original[0] + original[2], left + 1);
  const bottom = Math.max(parent[1], original[1] + original[3], top + 1);
  const height = 180;
  const scale = Math.max(0.001, Math.min(Math.max(1, width - 48) / (right - left), (height - 40) / (bottom - top)));
  const ox = width / 2 - (left + right) / 2 * scale;
  const oy = height / 2 - (top + bottom) / 2 * scale;
  const valid = value.every(Number.isFinite) && value[2] >= 0 && value[3] >= 0;
  const box = valid ? value : original;
  const start = (e: PointerEvent<HTMLButtonElement>, edge?: Edge) => {
    if (disabled || !valid || e.button !== 0 || gesture.current) return;
    e.preventDefault();
    e.currentTarget.focus();
    e.currentTarget.setPointerCapture(e.pointerId);
    gesture.current = { id: e.pointerId, x: e.clientX, y: e.clientY, box: [...value], scale, edge };
  };
  const move = (e: PointerEvent<HTMLButtonElement>) => {
    const active = gesture.current;
    if (!active || disabled || active.id !== e.pointerId) return;
    onChange(shift(active.box, (e.clientX - active.x) / active.scale, (e.clientY - active.y) / active.scale, active.edge));
  };
  const finish = (e: PointerEvent<HTMLButtonElement>, cancel = false) => {
    const active = gesture.current;
    if (active?.id !== e.pointerId) return;
    if (cancel) onChange(active.box);
    gesture.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
  };
  const key = (e: KeyboardEvent<HTMLButtonElement>, edge?: Edge) => {
    if (e.nativeEvent.isComposing || disabled || !valid) return;
    if (e.key === "Escape" && gesture.current) {
      e.preventDefault(); e.stopPropagation();
      onChange(gesture.current.box);
      const id = gesture.current.id;
      gesture.current = null;
      if (e.currentTarget.hasPointerCapture(id)) e.currentTarget.releasePointerCapture(id);
      return;
    }
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const step = e.shiftKey ? 10 : 1;
    const delta: Record<string, [number, number]> = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
    if (!delta[e.key]) return;
    e.preventDefault(); e.stopPropagation();
    onChange(shift(value, ...delta[e.key], edge));
  };
  const events = {
    onPointerMove: move,
    onPointerUp: (e: PointerEvent<HTMLButtonElement>) => finish(e),
    onPointerCancel: (e: PointerEvent<HTMLButtonElement>) => finish(e, true),
    onLostPointerCapture: () => { gesture.current = null; },
  };
  return <div ref={host} role="group" aria-label={t("ui_frame")} className="relative h-45 overflow-hidden rounded-lg border bg-muted/20"
    style={{ backgroundImage: "radial-gradient(var(--border) 1px, transparent 1px)", backgroundSize: "12px 12px" }}>
    <div aria-hidden="true" className="absolute border border-dashed border-muted-foreground/40 bg-background/40" style={{ left: ox, top: oy, width: parent[0] * scale, height: parent[1] * scale }} />
    <div className="absolute" style={{ left: ox + box[0] * scale, top: oy + box[1] * scale, width: Math.max(20, box[2] * scale), height: Math.max(20, box[3] * scale) }}>
      <button type="button" aria-label={t("ui_move_frame")} title={t("ui_move_frame")} disabled={disabled || !valid}
        className="absolute inset-0 flex items-center justify-center rounded-sm border-2 border-primary bg-primary/15 text-primary touch-none cursor-move focus-visible:outline-2 focus-visible:outline-ring disabled:cursor-default"
        onPointerDown={e => start(e)} onKeyDown={e => key(e)} {...events}><Move className="size-4 pointer-events-none" /></button>
      {edges.map(({ edge, name, cursor }) => <button type="button" key={name} disabled={disabled || !valid}
        aria-label={t("ui_resize_frame", { edge: t(`ui_edge_${name}`) })} title={t("ui_resize_frame", { edge: t(`ui_edge_${name}`) })}
        className="absolute z-10 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-[2px] border border-primary bg-background touch-none after:absolute after:-inset-1 hover:bg-primary/20 focus-visible:ring-2 focus-visible:ring-ring"
        style={{ left: `${(edge.x + 1) * 50}%`, top: `${(edge.y + 1) * 50}%`, cursor }}
        onPointerDown={e => start(e, edge)} onKeyDown={e => key(e, edge)} {...events} />)}
    </div>
  </div>;
}
