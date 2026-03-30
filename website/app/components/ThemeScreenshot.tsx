"use client";

import Image from "next/image";
import { useTheme } from "../context/ThemeContext";
import { ThemeToggle } from "./ThemeToggle";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

export function ThemeScreenshot({ title, desc }: { title: string; desc: string }) {
  const { theme } = useTheme();

  return (
    <section className="py-16 px-6 border-t border-border">
      <div className="max-w-2xl mx-auto">
        <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-center mb-2">
          {title}
        </h2>
        <p className="text-muted text-center text-sm mb-6 max-w-xl mx-auto">{desc}</p>
        <div className="flex mb-4 justify-center">
          <ThemeToggle />
        </div>
        <div className="rounded-xl overflow-hidden relative opacity-75 hover:opacity-100 transition-opacity">
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
