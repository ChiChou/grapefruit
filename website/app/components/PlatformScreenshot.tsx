"use client";

import { useState } from "react";
import Image from "next/image";
import { siApple, siAndroid } from "simple-icons";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

export function PlatformScreenshot() {
  const [platform, setPlatform] = useState<"ios" | "android">("ios");

  return (
    <div className="mt-16 relative">
      <div className="rounded-xl overflow-hidden relative mb-3">
        <Image
          src={`${base}/screenshot-droid.webp`}
          alt="Grapefruit Android workspace"
          width={1200}
          height={750}
          className={`w-full transition-opacity duration-300 ${platform === "android" ? "opacity-100" : "opacity-0"}`}
          priority
        />
        <Image
          src={`${base}/screenshot-fruity.webp`}
          alt="Grapefruit iOS workspace"
          width={1200}
          height={750}
          className={`w-full absolute inset-0 transition-opacity duration-300 ${platform === "ios" ? "opacity-100" : "opacity-0"}`}
          priority
        />
      </div>
      <div className="inline-flex justify-center rounded-lg border border-border overflow-hidden">
        {([["ios", siApple], ["android", siAndroid]] as const).map(([key, icon], i) => (
          <button
            key={key}
            onClick={() => setPlatform(key)}
            className={`inline-flex items-center px-3 py-1.5 transition-colors ${
              i > 0 ? "border-l border-border" : ""
            } ${
              platform === key
                ? "bg-surface text-fg"
                : "text-muted hover:text-fg"
            }`}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <path d={icon.path} />
            </svg>
          </button>
        ))}
      </div>
    </div>
  );
}
