"use client";

import { useState } from "react";
import Image from "next/image";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

const FEATURES = ["hook", "browse", "runtime", "disasm", "webview", "url"] as const;

type Strings = Record<string, string>;

export function FeatureCarousel({ t }: { t: Strings }) {
  const [active, setActive] = useState<(typeof FEATURES)[number]>("hook");

  return (
    <section className="py-24 px-6 border-t border-border">
      <div className="max-w-6xl mx-auto">
        <div className="flex flex-wrap justify-center gap-2 mb-8">
          {FEATURES.map((key) => (
            <button
              key={key}
              onClick={() => setActive(key)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                active === key
                  ? "bg-accent/15 text-accent border border-accent/30"
                  : "text-muted hover:text-fg border border-transparent hover:border-border"
              }`}
            >
              {t[`h_${key}_title`]}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
          <div className="order-2 md:order-1">
            <h3 className="text-2xl font-bold tracking-tight mb-3">
              {t[`h_${active}_title`]}
            </h3>
            <p className="text-muted leading-relaxed">
              {t[`h_${active}_desc`]}
            </p>
          </div>
          <div className="order-1 md:order-2 relative aspect-[4/3] rounded-xl overflow-hidden">
            {FEATURES.map((key) => (
              <Image
                key={key}
                src={`${base}/${t[`h_${key}_img`]}.webp`}
                alt={t[`h_${key}_title`]}
                fill
                className={`object-cover object-left-top transition-opacity duration-300 ${
                  active === key ? "opacity-75 hover:opacity-100" : "opacity-0"
                }`}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
