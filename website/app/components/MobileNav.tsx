"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ThemeToggle } from "./ThemeToggle";

type Item = { href: string; label: string; accent?: boolean };

export function MobileNav({ nav }: { nav: Item[] }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        className="md:hidden text-muted hover:text-fg p-1"
        onClick={() => setOpen((v) => !v)}
        aria-label="Toggle navigation"
      >
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="transition-transform duration-200">
          <line x1="3" y1="5" x2="17" y2="5"
            className="origin-center transition-all duration-200"
            style={open ? { transform: "translateY(5px) rotate(45deg)" } : {}} />
          <line x1="3" y1="10" x2="17" y2="10"
            className="transition-opacity duration-200"
            style={open ? { opacity: 0 } : {}} />
          <line x1="3" y1="15" x2="17" y2="15"
            className="origin-center transition-all duration-200"
            style={open ? { transform: "translateY(-5px) rotate(-45deg)" } : {}} />
        </svg>
      </button>

      <nav
        className={`md:hidden absolute top-14 left-0 right-0 border-b border-border bg-bg/95 backdrop-blur-lg px-6 z-40 overflow-hidden transition-all duration-200 ease-out ${
          open ? "max-h-96 py-4 opacity-100" : "max-h-0 py-0 opacity-0 border-b-0"
        }`}
      >
        <div className="space-y-1">
          {nav.map((item, i) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setOpen(false)}
              className={`block px-3 py-1.5 rounded-md text-sm transition-all duration-200 ${
                pathname === item.href
                  ? "bg-surface text-fg font-medium"
                  : item.accent
                    ? "text-accent-dim hover:text-accent"
                    : "text-muted hover:text-fg"
              }`}
              style={{
                transitionDelay: open ? `${i * 25}ms` : "0ms",
                transform: open ? "translateX(0)" : "translateX(-8px)",
                opacity: open ? 1 : 0,
              }}
            >
              {item.label}
            </Link>
          ))}
          <div className="pt-3 px-3">
            <ThemeToggle />
          </div>
        </div>
      </nav>
    </>
  );
}
