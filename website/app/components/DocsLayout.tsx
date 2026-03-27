"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";

export function DocsLayout({
  children,
  prefix = "",
  langHref,
  langLabel,
}: {
  children: React.ReactNode;
  prefix?: string;
  langHref: string;
  langLabel: string;
}) {
  const pathname = usePathname();

  const isZh = prefix === "/cn";

  const nav = [
    { href: `${prefix}/docs`, label: isZh ? "项目概览" : "Overview" },
    { href: `${prefix}/docs/install`, label: isZh ? "安装指南" : "Installation" },
    { href: `${prefix}/docs/limits`, label: isZh ? "已知限制" : "Known Limitations", accent: true },
    { href: `${prefix}/docs/analysis`, label: isZh ? "分析与反编译" : "Analysis & Decompilation" },
    { href: `${prefix}/docs/instrumentation`, label: isZh ? "动态插桩" : "Instrumentation" },
    { href: `${prefix}/docs/files`, label: isZh ? "文件浏览器" : "File Browser & Previews" },
    { href: `${prefix}/docs/data`, label: isZh ? "数据审查" : "Data Inspection" },
    { href: `${prefix}/docs/platforms`, label: isZh ? "平台特性" : "Platform Features" },
    { href: `${prefix}/docs/llm`, label: isZh ? "LLM 配置" : "LLM Configuration" },
    { href: `${prefix}/docs/arch`, label: isZh ? "架构内部" : "Architecture Internals" },
  ];

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <header className="border-b border-border bg-bg/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-6xl mx-auto flex items-center justify-between h-14 px-6">
          <a href={prefix || "/"} className="flex items-center gap-2.5">
            <Image src="/logo.svg" alt="Grapefruit" width={24} height={24} />
            <span className="font-semibold tracking-tight text-sm">
              Grapefruit Docs
            </span>
          </a>
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/chichou/grapefruit"
              className="text-muted hover:text-fg text-sm"
              target="_blank"
              rel="noopener"
            >
              GitHub
            </a>
            <a
              href={langHref}
              className="text-muted hover:text-fg text-xs font-mono border border-border rounded px-2 py-0.5"
            >
              {langLabel}
            </a>
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto flex min-h-[calc(100dvh-3.5rem)]">
        <aside className="hidden md:block w-56 shrink-0 border-r border-border py-8 pr-6 pl-6 sticky top-14 h-[calc(100dvh-3.5rem)] overflow-auto">
          <nav className="space-y-1">
            {nav.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`block px-3 py-1.5 rounded-md text-sm transition-colors ${
                  pathname === item.href
                    ? "bg-surface text-fg font-medium"
                    : "accent" in item
                      ? "text-accent-dim hover:text-accent"
                      : "text-muted hover:text-fg"
                }`}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </aside>

        <main className="flex-1 px-6 md:px-12 py-8 max-w-3xl">{children}</main>
      </div>
    </div>
  );
}
