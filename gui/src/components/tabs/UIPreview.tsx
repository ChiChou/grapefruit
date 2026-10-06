import { useState, useRef, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { X, RotateCcw, ArrowUpRight } from "lucide-react";
import { UIFrame } from "./UIFrame";
import type { Box } from "@/lib/frame";
import { useZoom } from "@/lib/use-zoom";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Button } from "@/components/ui/button";
import type { UIDumpNode, UIChanges } from "@agent/fruity/modules/ui";

export function UIPreview({ tree, mode, selected, hovered, onHover, onSelect, onModeChange }: {
  tree: UIDumpNode;
  mode: "screenshot" | "3d";
  selected: string | null;
  hovered: string | null;
  onHover: (node: UIDumpNode | null) => void;
  onSelect: (node: UIDumpNode) => void;
  onModeChange: () => void;
}) {
  const { t } = useTranslation();
  const host = useRef<HTMLDivElement>(null);
  const drag = useRef<{ id: number; x: number; y: number; moved: boolean } | null>(null);
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const pinch = useRef<{ distance: number; center: { x: number; y: number } } | null>(null);
  const suppress = useRef(false);
  const [size, setSize] = useState({ width: 400, height: 500 });
  const [rotation, setRotation] = useState({ x: -20, y: -30 });
  const [spacing, setSpacing] = useState(20);
  const zoom = useZoom(host, mode === "3d");
  useEffect(() => {
    if (!host.current) return;
    const observer = new ResizeObserver(([entry]) => setSize({ width: entry.contentRect.width, height: entry.contentRect.height }));
    observer.observe(host.current);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    pointers.current.clear();
    pinch.current = null;
    drag.current = null;
    suppress.current = false;
  }, [mode]);
  const nodes = useMemo(() => {
    const result: { node: UIDumpNode; depth: number }[] = [];
    function walk(node: UIDumpNode, depth: number) {
      if (node.visible && node.frame) result.push({ node, depth });
      node.children?.forEach(child => walk(child, depth + 1));
    }
    walk(tree, 0);
    return result;
  }, [tree]);
  const [width, height] = tree.bounds[1];
  const fit = Math.min((size.width - 80) / width, (size.height - 80) / height, 1) * zoom.view.zoom;
  const scale = Math.max(0.05, fit);
  const origin = tree.bounds[0];
  const center = Math.max(0, ...nodes.map(({ depth }) => depth)) / 2;
  const active = nodes.find(({ node }) => node.id === selected)?.node;
  return <div className="flex flex-col h-full min-h-0">
    <div className="grid grid-cols-[minmax(2.5rem,1fr)_minmax(0,auto)_minmax(2.5rem,1fr)] items-center gap-3 p-2 border-b text-xs min-h-12">
      <Button size="sm" className="justify-self-start" variant={mode === "3d" ? "default" : "outline"} aria-pressed={mode === "3d"} onClick={onModeChange}>{t("ui_3d")}</Button>
      <div className="flex flex-wrap justify-center items-center gap-x-3 gap-y-2 min-w-0 min-h-8">
      {mode === "3d" && <div className="flex shrink-0 items-center gap-2">
        <span>{t("ui_spacing")}</span>
        <Slider aria-label={t("ui_spacing")} className="w-24" min={0} max={80} step={1} value={[spacing]}
          onValueChange={value => setSpacing(Array.isArray(value) ? value[0] : value)} />
        <span className="w-5 tabular-nums text-right">{spacing}</span>
      </div>}
      <div className="flex shrink-0 items-center gap-2">
        <span>{t("ui_zoom")}</span>
        <Slider aria-label={t("ui_zoom")} className="w-24" min={0.25} max={4} step={0.01} value={[zoom.view.zoom]}
          onValueChange={value => zoom.set(Array.isArray(value) ? value[0] : value)} />
      </div>
      </div>
      <Tooltip>
        <TooltipTrigger render={<Button size="icon-sm" variant="ghost" className="justify-self-end" aria-label={t("ui_reset")}
          onClick={() => { setRotation({ x: -20, y: -30 }); setSpacing(20); zoom.reset(); }} />}><RotateCcw /></TooltipTrigger>
        <TooltipContent>{t("ui_reset")}</TooltipContent>
      </Tooltip>
    </div>
    <div ref={host} className="flex-1 relative overflow-hidden bg-muted/30" style={{ perspective: 1600, touchAction: "none" }}
      onPointerDown={e => {
        if (mode !== "3d" || e.button !== 0) return;
        pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (pointers.current.size >= 2) {
          const [a, b] = [...pointers.current.values()];
          pinch.current = { distance: Math.hypot(b.x - a.x, b.y - a.y), center: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
          drag.current = null;
          suppress.current = true;
          for (const id of pointers.current.keys()) e.currentTarget.setPointerCapture(id);
        } else {
          suppress.current = false;
          drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY, moved: false };
        }
      }}
      onPointerMove={e => {
        if (!pointers.current.has(e.pointerId)) return;
        pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (pointers.current.size >= 2) {
          const [a, b] = [...pointers.current.values()];
          const next = { distance: Math.hypot(b.x - a.x, b.y - a.y), center: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
          const before = pinch.current;
          if (before && before.distance > 0) zoom.at(next.distance / before.distance, next.center, before.center);
          pinch.current = next;
          return;
        }
        const prev = drag.current;
        if (!prev || prev.id !== e.pointerId) return;
        const dx = e.clientX - prev.x;
        const dy = e.clientY - prev.y;
        if (!prev.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
        e.currentTarget.setPointerCapture(e.pointerId);
        suppress.current = true;
        setRotation(r => ({ x: Math.max(-80, Math.min(80, r.x - dy * 0.4)), y: r.y + dx * 0.4 }));
        drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY, moved: true };
      }}
      onPointerUp={e => {
        pointers.current.delete(e.pointerId);
        pinch.current = null;
        drag.current = null;
        if (suppress.current) e.preventDefault();
        if (pointers.current.size === 0) {
          // Keep gesture releases from also selecting a layer.
          setTimeout(() => { suppress.current = false; }, 0);
        }
        if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
      }}
      onPointerCancel={e => {
        pointers.current.delete(e.pointerId);
        pinch.current = null;
        drag.current = null;
        if (pointers.current.size === 0) suppress.current = false;
      }}
      onLostPointerCapture={e => {
        if (e.target !== e.currentTarget) return;
        pointers.current.delete(e.pointerId);
        pinch.current = null;
        drag.current = null;
      }}
      onPointerLeave={e => {
        if (!e.currentTarget.hasPointerCapture(e.pointerId)) {
          pointers.current.delete(e.pointerId);
          drag.current = null;
        }
      }}>
      <div style={{ position: "absolute", left: "50%", top: "50%", width, height, marginLeft: -width / 2, marginTop: -height / 2,
        transformStyle: "preserve-3d", transform: `translate(${zoom.view.x}px, ${zoom.view.y}px) scale(${scale}) ${mode === "3d" ? `rotateX(${rotation.x}deg) rotateY(${rotation.y}deg)` : ""}` }}>
        {mode === "screenshot" && tree.screenshot && <img draggable={false} alt={t("ui_screenshot")} src={`data:image/png;base64,${tree.screenshot}`} className="absolute inset-0 w-full h-full pointer-events-none" />}
        {nodes.map(({ node, depth }) => {
          const frame = node.frame!;
          const clip = node.clip;
          const inset = clip ? `${Math.max(0, (clip[0][1] - frame[0][1]) / frame[1][1] * 100)}% ${Math.max(0, (frame[0][0] + frame[1][0] - clip[0][0] - clip[1][0]) / frame[1][0] * 100)}% ${Math.max(0, (frame[0][1] + frame[1][1] - clip[0][1] - clip[1][1]) / frame[1][1] * 100)}% ${Math.max(0, (clip[0][0] - frame[0][0]) / frame[1][0] * 100)}%` : "0";
          return <button key={node.id} aria-label={node.clazz} title={node.description || node.clazz} data-ui-layer={node.id} data-selected={node.id === selected} data-hovered={node.id === hovered}
            onMouseEnter={() => { if (!drag.current?.moved && !pinch.current) onHover(node); }} onMouseLeave={() => onHover(null)}
            onClick={e => { e.stopPropagation(); if (!suppress.current) onSelect(node); }}
            style={{ position: "absolute", left: frame[0][0] - origin[0], top: frame[0][1] - origin[1], width: frame[1][0], height: frame[1][1],
              clipPath: `inset(${inset})`,
              transform: mode === "3d" ? `translateZ(${(depth - center) * spacing}px)` : undefined,
              border: `${node.id === selected || node.id === hovered ? 3 : 1}px solid ${node.id === selected ? "#f59e0b" : node.id === hovered ? "#06b6d4" : mode === "3d" ? "#38bdf855" : "transparent"}`,
              background: mode === "3d" && !node.image ? "#38bdf80a" : "transparent", padding: 0 }}>
            {mode === "3d" && node.image && <img alt="" draggable={false} src={`data:image/png;base64,${node.image}`} className="w-full h-full pointer-events-none" />}
          </button>;
        })}
        {mode === "screenshot" && nodes.filter(({ node }) => node.id === selected || node.id === hovered).map(({ node }) => <div key={`outline:${node.id}`} aria-hidden="true"
          style={{ position: "absolute", pointerEvents: "none", left: node.frame![0][0] - origin[0], top: node.frame![0][1] - origin[1], width: node.frame![1][0], height: node.frame![1][1], border: `3px solid ${node.id === selected ? "#f59e0b" : "#06b6d4"}` }} />)}
      </div>
      {active && <div className="absolute bottom-2 left-2 px-2 py-1 bg-background/90 text-xs pointer-events-none">{active.clazz}</div>}
    </div>
  </div>;
}

export function UIEditor({ node, busy, onApply, onDismiss, onOpenClass, parent }: {
  node: UIDumpNode;
  busy: boolean;
  onApply: (changes: UIChanges) => void;
  onDismiss: () => void;
  onOpenClass: (name: string) => void;
  parent: [number, number];
}) {
  const { t } = useTranslation();
  const [text, setText] = useState(node.text ?? "");
  const [hidden, setHidden] = useState(node.hidden);
  const [alpha, setAlpha] = useState(String(node.alpha));
  const original = [...node.localFrame[0], ...node.localFrame[1]];
  const initial = original.map(value => String(Number(value.toFixed(2))));
  const [frame, setFrame] = useState(initial);
  const values = frame.map((value, i) => value === initial[i] ? original[i] : Number(value));
  const valid = frame.every(v => v.trim() !== "") && values.every(Number.isFinite) && values[2] >= 0 && values[3] >= 0 && alpha.trim() !== "" && Number.isFinite(Number(alpha)) && Number(alpha) >= 0 && Number(alpha) <= 1;
  const frameChanged = values.some((value, i) => value !== original[i]);
  const changed = (node.text !== undefined && text !== node.text) || hidden !== node.hidden || Number(alpha) !== node.alpha || frameChanged;
  return <form className="flex flex-col text-xs" onKeyDown={e => {
    if (e.nativeEvent.isComposing || e.defaultPrevented) return;
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); onDismiss(); }
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key === "Enter" && valid && changed && !busy) {
      e.preventDefault(); e.stopPropagation(); e.currentTarget.requestSubmit();
    }
  }} onSubmit={e => {
    e.preventDefault();
    if (!valid || !changed || busy) return;
    const changes: UIChanges = {};
    if (node.text !== undefined && text !== node.text) changes.text = text;
    if (hidden !== node.hidden) changes.hidden = hidden;
    if (Number(alpha) !== node.alpha) changes.alpha = Number(alpha);
    if (frameChanged) {
      changes.frame = [[values[0], values[1]], [values[2], values[3]]];
    }
    onApply(changes);
  }}>
    <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b bg-background/95 p-3 backdrop-blur-sm">
      <div className="min-w-0 space-y-1">
        <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("ui_properties")}</p>
        <button type="button" className="group inline-flex items-start gap-1 text-left font-mono text-xs font-medium leading-relaxed hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={() => onOpenClass(node.clazz)}><span className="break-all">{node.clazz}</span><ArrowUpRight className="mt-0.5 size-3 shrink-0 text-muted-foreground group-hover:text-foreground" /></button>
      </div>
      <Button type="button" variant="ghost" size="icon-xs" aria-label={t("dismiss")} aria-keyshortcuts="Escape" title={`${t("dismiss")} (Esc)`} onClick={onDismiss}><X /></Button>
    </header>
    <fieldset disabled={busy} className="space-y-4 p-3 disabled:opacity-60">
      {node.text !== undefined && <section className="space-y-2">
        <label className="flex flex-col gap-2">
          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("ui_text")}</span>
          <Textarea aria-label={t("ui_text")} className="resize-y min-h-20 text-xs md:text-xs" rows={3} value={text} onChange={e => setText(e.target.value)} disabled={busy} />
        </label>
      </section>}
      <section className="space-y-2" aria-label={t("ui_appearance")}>
        <h4 className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("ui_appearance")}</h4>
        <div className="rounded-lg border bg-muted/15 divide-y divide-border/60">
          <div className="flex items-center justify-between gap-3 px-3 py-2.5">
            <span>{t("ui_hidden")}</span>
            <Switch aria-label={t("ui_hidden")} size="sm" checked={hidden} onCheckedChange={setHidden} disabled={busy} />
          </div>
          <div className="flex items-center justify-between gap-3 px-3 py-3">
            <span>{t("ui_alpha")}</span>
            <div className="flex min-w-0 flex-1 items-center justify-end gap-3">
              <Slider aria-label={t("ui_alpha")} className="max-w-36 min-w-16" min={0} max={1} step={0.01} value={[Number(alpha)]} disabled={busy}
                onValueChange={value => setAlpha(String(Array.isArray(value) ? value[0] : value))} />
              <span className="w-9 shrink-0 text-right font-mono tabular-nums">{Math.round(Number(alpha) * 100)}%</span>
            </div>
          </div>
        </div>
      </section>
      <section className="space-y-2" aria-label={t("ui_frame")}>
        <div className="flex items-center justify-between">
          <h4 className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("ui_frame")}</h4>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground">{t("ui_points")}</span>
            <Tooltip>
              <TooltipTrigger render={<Button type="button" size="icon-xs" variant="ghost" aria-label={t("ui_reset_frame")}
                disabled={busy || !frameChanged} onClick={() => setFrame(initial)} />}><RotateCcw /></TooltipTrigger>
              <TooltipContent>{t("ui_reset_frame")}</TooltipContent>
            </Tooltip>
          </div>
        </div>
        <UIFrame value={values as Box} original={original as Box} parent={parent} disabled={busy}
          onChange={next => setFrame(prev => next.map((value, i) => value === values[i] ? prev[i] : String(Number(value.toFixed(2)))))} />
        <div className="grid grid-cols-2 gap-2">{["X", "Y", t("ui_width"), t("ui_height")].map((label, i) => <label key={i} className="flex flex-col gap-1.5">
          <span className="text-[11px] text-muted-foreground">{label}</span>
          <Input aria-label={label} className="h-8 font-mono text-xs md:text-xs tabular-nums" type="number" step="any" min={i >= 2 ? 0 : undefined} value={frame[i]} onChange={e => setFrame(prev => prev.map((v, j) => j === i ? e.target.value : v))} />
        </label>)}</div>
        <p className="text-[11px] leading-relaxed text-muted-foreground">{t("ui_frame_hint")}</p>
      </section>
    </fieldset>
    <section className="space-y-3 border-t p-3">
      {node.delegate?.name && <div className="space-y-1">
        <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("ui_delegate")}</p>
        <button type="button" className="group inline-flex items-start gap-1 text-left font-mono text-[11px] leading-relaxed hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={() => onOpenClass(node.delegate!.name!)}><span className="break-all">{node.delegate.name}</span><ArrowUpRight className="mt-0.5 size-3 shrink-0 text-muted-foreground group-hover:text-foreground" /></button>
      </div>}
      {node.description && <div className="space-y-2">
        <h4 className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("ui_description")}</h4>
        <p className="rounded-md border bg-muted/15 px-2.5 py-2 font-mono text-[10px] leading-relaxed break-all text-muted-foreground">{node.description}</p>
      </div>}
    </section>
    <footer className="sticky bottom-0 flex items-center justify-between gap-2 border-t bg-background/95 p-3 backdrop-blur-sm">
      <span className="text-[11px] text-muted-foreground">{t(changed ? "ui_unsaved" : "ui_no_changes")}</span>
      <Button type="submit" size="sm" className="text-xs" aria-keyshortcuts="Control+Enter Meta+Enter" title={`${t("ui_apply")} (Ctrl/⌘+Enter)`} disabled={!valid || !changed || busy}>{t("ui_apply")}</Button>
    </footer>
  </form>;
}
