"use client";

import { useState } from "react";
import Image from "next/image";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

export function PlatformScreenshot() {
  const [platform, setPlatform] = useState<"ios" | "android">("ios");

  return (
    <div className="mt-16 relative">
      <div className="flex gap-1 mb-3 justify-center">
        <button
          onClick={() => setPlatform("ios")}
          className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            platform === "ios"
              ? "bg-surface text-fg border border-border"
              : "text-muted hover:text-fg"
          }`}
        >
          iOS
        </button>
        <button
          onClick={() => setPlatform("android")}
          className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            platform === "android"
              ? "bg-surface text-fg border border-border"
              : "text-muted hover:text-fg"
          }`}
        >
          Android
        </button>
      </div>
      <div className="rounded-xl overflow-hidden relative">
        <Image
          src={`${base}/screenshot-droid.png`}
          alt="Grapefruit Android workspace"
          width={1200}
          height={750}
          className={`w-full transition-opacity duration-300 ${platform === "android" ? "opacity-100" : "opacity-0"}`}
          priority
        />
        <Image
          src={`${base}/screenshot-fruity.png`}
          alt="Grapefruit iOS workspace"
          width={1200}
          height={750}
          className={`w-full absolute inset-0 transition-opacity duration-300 ${platform === "ios" ? "opacity-100" : "opacity-0"}`}
          priority
        />
      </div>
    </div>
  );
}
