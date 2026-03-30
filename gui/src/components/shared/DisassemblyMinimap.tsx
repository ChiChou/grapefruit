import { useCallback, useEffect, useMemo, useRef, useState } from "react";

interface MinimapSection {
  name: string;
  vaddr: number;
  size: number;
  perm: string;
}

interface MinimapFunction {
  addr: number;
  size: number;
  name: string;
}

interface Props {
  cmd: (command: string) => Promise<string>;
  isReady: boolean;
  currentAddr?: string;
  functions?: Array<{ addr: string; name: string; size: number }>;
  onSeek?: (addr: string, fnName?: string) => void;
}

function parseAddr(s: string): number {
  if (s.startsWith("0x")) return parseInt(s, 16);
  return parseInt(s, 10);
}

function readCssVar(name: string, fallback: string): string {
  if (typeof getComputedStyle === "undefined") return fallback;
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

export function DisassemblyMinimap({ cmd, isReady, currentAddr, functions: propFns, onSeek }: Props) {
  const [sections, setSections] = useState<MinimapSection[]>([]);
  const [fnList, setFnList] = useState<MinimapFunction[]>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const externalFns = useMemo<MinimapFunction[] | null>(() => {
    if (!propFns?.length) return null;
    return propFns.map((f) => ({
      addr: parseAddr(f.addr),
      size: f.size,
      name: f.name,
    }));
  }, [propFns]);

  const fns = externalFns ?? fnList;

  useEffect(() => {
    if (!isReady) return;
    let cancelled = false;

    (async () => {
      try {
        const cmds = [cmd("iSj")];
        if (!externalFns) cmds.push(cmd("aflj"));
        const results = await Promise.all(cmds);

        if (cancelled) return;
        try {
          const arr = JSON.parse(results[0]);
          setSections(
            (Array.isArray(arr) ? arr : [])
              .filter((s: any) => s.size > 0)
              .map((s: any) => ({
                name: s.name ?? "",
                vaddr: s.vaddr ?? 0,
                size: s.size ?? 0,
                perm: s.perm ?? "",
              })),
          );
        } catch {}

        if (!externalFns && results[1]) {
          try {
            const arr = JSON.parse(results[1]);
            setFnList(
              (Array.isArray(arr) ? arr : []).map((f: any) => ({
                addr: f.offset ?? f.addr ?? 0,
                size: f.size ?? 0,
                name: f.name ?? "",
              })),
            );
          } catch {}
        }
      } catch {}
    })();

    return () => { cancelled = true; };
  }, [cmd, isReady, externalFns]);

  const range = useMemo(() => {
    if (sections.length === 0) return null;
    let lo = Infinity;
    let hi = 0;
    for (const s of sections) {
      if (s.vaddr < lo) lo = s.vaddr;
      if (s.vaddr + s.size > hi) hi = s.vaddr + s.size;
    }
    return { lo, hi, span: hi - lo || 1 };
  }, [sections]);

  const currentOffset = useMemo(() => {
    if (!currentAddr) return null;
    const n = parseAddr(currentAddr);
    return Number.isFinite(n) ? n : null;
  }, [currentAddr]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !range) return;

    const rect = container.getBoundingClientRect();
    const w = Math.round(rect.width);
    const h = Math.round(rect.height);
    const dpr = window.devicePixelRatio || 1;

    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const sectionColor = readCssVar("--r2-minimap-section", "rgba(100,160,100,0.3)");
    const fnColor = readCssVar("--r2-minimap-fn", "rgba(34,211,238,0.5)");
    const cursorColor = readCssVar("--r2-minimap-cursor", "rgba(239,68,68,0.9)");

    const toY = (addr: number) => ((addr - range.lo) / range.span) * h;

    for (const s of sections) {
      const y = toY(s.vaddr);
      const sh = Math.max((s.size / range.span) * h, 1);
      ctx.fillStyle = sectionColor;
      ctx.fillRect(0, y, w, sh);
    }

    for (const f of fns) {
      const y = toY(f.addr);
      const fh = Math.max((f.size / range.span) * h, 0.5);
      ctx.fillStyle = fnColor;
      ctx.fillRect(0, y, w * 0.6, fh);
    }

    if (currentOffset != null && currentOffset >= range.lo && currentOffset <= range.hi) {
      const y = toY(currentOffset);
      ctx.fillStyle = cursorColor;
      ctx.fillRect(0, y - 1, w, 3);
    }
  }, [sections, fns, range, currentOffset]);

  useEffect(() => { draw(); }, [draw]);

  useEffect(() => {
    const obs = new ResizeObserver(() => draw());
    if (containerRef.current) obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, [draw]);

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      if (!range || !onSeek || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const ratio = (e.clientY - rect.top) / rect.height;
      const clickAddr = Math.round(range.lo + ratio * range.span);

      let best: MinimapFunction | null = null;
      let bestDist = Infinity;
      for (const f of fns) {
        if (clickAddr >= f.addr && clickAddr < f.addr + f.size) {
          best = f;
          break;
        }
        const dist = Math.abs(f.addr - clickAddr);
        if (dist < bestDist) {
          bestDist = dist;
          best = f;
        }
      }

      const addr = `0x${clickAddr.toString(16)}`;
      onSeek(best ? `0x${best.addr.toString(16)}` : addr, best?.name);
    },
    [range, onSeek, fns],
  );

  if (sections.length === 0) return null;

  return (
    <div
      ref={containerRef}
      className="h-full w-10 border-l cursor-pointer shrink-0"
      onClick={handleClick}
    >
      <canvas ref={canvasRef} className="block" />
    </div>
  );
}
