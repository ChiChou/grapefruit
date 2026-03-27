"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

export function CopyInstall({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  const Icon = copied ? Check : Copy;

  return (
    <div className="relative inline-flex flex-col items-center">
      <div className="absolute -inset-4 rounded-2xl bg-accent/5 blur-xl" />
      <button
        onClick={copy}
        className="relative group inline-flex items-center justify-between gap-3 pl-6 pr-3 py-3 rounded-xl bg-surface border border-accent/20 hover:border-accent/40 font-mono text-base sm:text-lg transition-colors cursor-pointer min-w-[220px] sm:min-w-[280px]"
      >
        <span className="inline-flex items-center gap-3">
          <span className="text-accent">$</span>
          <span>{cmd}</span>
        </span>
        <Icon size={16} className={`transition-opacity ${copied ? "opacity-80 text-green-400" : "opacity-40 group-hover:opacity-80 text-muted"}`} />
      </button>
    </div>
  );
}
