"use client";

import { useState } from "react";
import Image from "next/image";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

export function ThemeScreenshot({ title, desc }: { title: string; desc: string }) {
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  return (
    <section className="py-24 px-6 border-t border-border">
      <div className="max-w-6xl mx-auto">
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-center mb-4">
          {title}
        </h2>
        <p className="text-muted text-center text-lg mb-8 max-w-2xl mx-auto">{desc}</p>
        <div className="flex gap-1 mb-6 justify-center">
          <button
            onClick={() => setTheme("dark")}
            className={`px-3 py-1.5 rounded-l-lg text-xs font-medium transition-colors border ${
              theme === "dark"
                ? "bg-surface text-fg border-border"
                : "text-muted hover:text-fg border-border border-r-0"
            }`}
          >
            <Moon />
          </button>
          <button
            onClick={() => setTheme("light")}
            className={`px-3 py-1.5 rounded-r-lg text-xs font-medium transition-colors border ${
              theme === "light"
                ? "bg-surface text-fg border-border"
                : "text-muted hover:text-fg border-border border-l-0"
            }`}
          >
            <Sun />
          </button>
        </div>
        <div className="rounded-xl overflow-hidden relative">
          <Image
            src={`${base}/dark.webp`}
            alt="Grapefruit dark theme"
            width={1200}
            height={750}
            className={`w-full transition-opacity duration-300 ${theme === "dark" ? "opacity-100" : "opacity-0"}`}
          />
          <Image
            src={`${base}/light.webp`}
            alt="Grapefruit light theme"
            width={1200}
            height={750}
            className={`w-full absolute inset-0 transition-opacity duration-300 ${theme === "light" ? "opacity-100" : "opacity-0"}`}
          />
        </div>
      </div>
    </section>
  );
}

function Moon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </svg>
  );
}

function Sun() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
    </svg>
  );
}
