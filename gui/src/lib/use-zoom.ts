import { useCallback, useEffect, useRef, useState, type RefObject } from "react";

type Point = { x: number; y: number };
type View = Point & { zoom: number };
const initial: View = { zoom: 1, x: 0, y: 0 };

export function useZoom(host: RefObject<HTMLElement | null>, enabled: boolean) {
  const [view, setView] = useState(initial);
  const current = useRef(initial);
  const target = useRef(initial);
  const frame = useRef<number | null>(null);

  const update = useCallback((next: View, immediate = false) => {
    target.current = next;
    if (immediate || matchMedia("(prefers-reduced-motion: reduce)").matches) {
      if (frame.current !== null) cancelAnimationFrame(frame.current);
      frame.current = null;
      current.current = next;
      setView(next);
      return;
    }
    if (frame.current !== null) return;
    let previous = performance.now();
    const step = (now: number) => {
      const amount = 1 - Math.exp(-Math.min(now - previous, 64) / 45);
      previous = now;
      const before = current.current;
      const goal = target.current;
      const next = {
        zoom: before.zoom + (goal.zoom - before.zoom) * amount,
        x: before.x + (goal.x - before.x) * amount,
        y: before.y + (goal.y - before.y) * amount,
      };
      const settled = Math.abs(next.zoom - goal.zoom) < 0.001 &&
        Math.abs(next.x - goal.x) < 0.1 && Math.abs(next.y - goal.y) < 0.1;
      current.current = settled ? goal : next;
      setView(current.current);
      frame.current = settled ? null : requestAnimationFrame(step);
    };
    frame.current = requestAnimationFrame(step);
  }, []);

  const at = useCallback((factor: number, to: Point, from = to) => {
    const rect = host.current?.getBoundingClientRect();
    if (!rect || !Number.isFinite(factor) || factor <= 0) return;
    const before = target.current;
    const zoom = Math.max(0.25, Math.min(4, before.zoom * factor));
    const ratio = zoom / before.zoom;
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    update({ zoom, x: to.x - cx - (from.x - cx - before.x) * ratio,
      y: to.y - cy - (from.y - cy - before.y) * ratio });
  }, [host, update]);

  const set = useCallback((value: number) => {
    const zoom = Math.max(0.25, Math.min(4, value));
    const ratio = zoom / target.current.zoom;
    update({ zoom, x: target.current.x * ratio, y: target.current.y * ratio });
  }, [update]);

  const reset = useCallback(() => update(initial, true), [update]);

  useEffect(() => {
    const el = host.current;
    if (!el || !enabled) return;
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      event.stopPropagation();
      const unit = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? el.clientHeight : 1;
      const delta = Math.max(-300, Math.min(300, event.deltaY * unit));
      at(Math.exp(-delta * (event.ctrlKey ? 0.01 : 0.002)), { x: event.clientX, y: event.clientY });
    };
    el.addEventListener("wheel", wheel, { passive: false });
    return () => el.removeEventListener("wheel", wheel);
  }, [host, enabled, at]);

  useEffect(() => () => {
    if (frame.current !== null) cancelAnimationFrame(frame.current);
  }, []);

  return { view, at, set, reset };
}
