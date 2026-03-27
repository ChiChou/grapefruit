"use client";

import { useEffect, useRef, useState } from "react";
import { Star } from "lucide-react";

const API = "https://api.github.com/repos/chichou/grapefruit";

function fmt(n: number) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);
}

function useCountUp(target: number | null, duration = 800) {
  const [value, setValue] = useState<number | null>(null);
  const raf = useRef<number>(0);

  useEffect(() => {
    if (target == null) return;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - (1 - t) ** 3;
      setValue(Math.round(ease * target));
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [target, duration]);

  return value;
}

export function StarButton({ href }: { href: string }) {
  const [stars, setStars] = useState<number | null>(null);
  const display = useCountUp(stars);

  useEffect(() => {
    fetch(API)
      .then((r) => r.json())
      .then((d) => setStars(d.stargazers_count))
      .catch(() => {});
  }, []);

  return (
    <a
      href={href}
      className="group inline-flex items-center rounded-lg border border-border/80 text-sm font-medium transition-colors hover:border-accent/40 overflow-hidden"
      target="_blank"
      rel="noreferrer"
    >
      <span className="inline-flex items-center gap-2 px-4 py-2 bg-[#1a1a1f] hover:bg-[#222228] transition-colors">
        <Star size={14} fill="currentColor" className="text-amber-400" />
        Star
      </span>
      <span className="px-4 py-2 bg-surface/60 text-fg font-mono tabular-nums border-l border-border/80 group-hover:text-accent transition-colors min-w-16 text-center">
        {display != null ? (
          fmt(display)
        ) : (
          <span className="inline-block w-[3ch] h-4 rounded bg-border/40 animate-pulse" />
        )}
      </span>
    </a>
  );
}
