"use client";

import { useTheme } from "../context/ThemeContext";

export function ThemeToggle({ className = "" }: { className?: string }) {
  const { theme, setTheme } = useTheme();

  return (
    <div className={`inline-flex rounded-lg border border-border overflow-hidden ${className}`}>
      <button
        onClick={() => setTheme("dark")}
        className={`px-3 py-1.5 text-xs font-medium transition-colors ${
          theme === "dark"
            ? "bg-surface text-fg"
            : "text-muted hover:text-fg"
        }`}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
        </svg>
      </button>
      <button
        onClick={() => setTheme("light")}
        className={`px-3 py-1.5 text-xs font-medium transition-colors border-l border-border ${
          theme === "light"
            ? "bg-surface text-fg"
            : "text-muted hover:text-fg"
        }`}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
        </svg>
      </button>
    </div>
  );
}
