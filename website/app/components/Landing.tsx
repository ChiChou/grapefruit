import Image from "next/image";
import Link from "next/link";
import { PlatformScreenshot } from "./PlatformScreenshot";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

type Strings = Record<string, string>;

const GITHUB = "https://github.com/chichou/grapefruit";
const MASTODON = "https://infosec.exchange/@codecolorist";
const SPONSOR = "https://github.com/sponsors/ChiChou";

const whyIcons = [Globe, Layers, Scale] as const;
const highlightIcons = [Hook, SearchIcon, Cpu] as const;

export function Landing({ t, langHref }: { t: Strings; langHref: string }) {
  return (
    <>
      <header className="fixed top-0 inset-x-0 z-50 border-b border-border/50 bg-bg/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto flex items-center justify-between h-14 px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <Image src={`${base}/logo.svg`} alt="Grapefruit" width={24} height={24} />
            <span className="font-semibold tracking-tight text-sm">Grapefruit</span>
          </Link>
          <nav className="flex items-center gap-6 text-sm text-muted">
            <Link href="/docs" className="hover:text-fg transition-colors">
              {t.nav_docs}
            </Link>
            <a href={GITHUB} className="hover:text-fg transition-colors" target="_blank" rel="noopener">
              {t.nav_github}
            </a>
            <a href={SPONSOR} className="hover:text-fg transition-colors inline-flex items-center gap-1" target="_blank" rel="noopener">
              <span className="text-red-500">&#9829;</span>
              {t.nav_sponsor}
            </a>
            <Link href={langHref} className="hover:text-fg transition-colors font-mono text-xs border border-border rounded px-2 py-0.5">
              {t.lang_switch}
            </Link>
          </nav>
        </div>
      </header>

      <main className="flex-1">
        <section className="relative pt-32 pb-20 px-6 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(255,167,69,0.08),transparent_60%)]" />
          <div className="relative max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-accent/20 bg-accent/5 text-accent text-xs font-medium mb-8">
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
              {t.hero_badge}
            </div>
            <h1 className="text-5xl sm:text-7xl font-bold tracking-tight leading-[1.1] mb-6">
              {t.hero_title}
            </h1>
            <p className="text-lg sm:text-xl text-muted max-w-2xl mx-auto mb-10 leading-relaxed">
              {t.hero_desc}
            </p>
            <div className="flex items-center justify-center gap-4">
              <a href={GITHUB} className="inline-flex items-center gap-2 px-6 py-3 bg-fg text-bg rounded-lg font-medium text-sm hover:bg-fg/90 transition-colors">
                {t.hero_cta}
                <Arrow />
              </a>
              <Link href={langHref === "/" ? "/cn/docs" : "/docs"} className="inline-flex items-center gap-2 px-6 py-3 border border-border rounded-lg font-medium text-sm text-muted hover:text-fg hover:border-fg/20 transition-colors">
                {t.hero_cta_docs}
              </Link>
            </div>
            <PlatformScreenshot />
          </div>
        </section>

        <section className="py-24 px-6">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-center mb-16">
              {t.why_title}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {(["1", "2", "3"] as const).map((key, i) => {
                const Icon = whyIcons[i];
                return (
                  <div key={key} className="text-center">
                    <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center mx-auto mb-4 text-accent">
                      <Icon />
                    </div>
                    <h3 className="font-semibold mb-2">{t[`why_${key}_title`]}</h3>
                    <p className="text-sm text-muted leading-relaxed">{t[`why_${key}_desc`]}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section className="py-24 px-6 border-t border-border">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-center mb-16">
              {t.highlights_title}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {(["hook", "browse", "disasm"] as const).map((key, i) => {
                const Icon = highlightIcons[i];
                return (
                  <div key={key} className="group p-6 rounded-xl border border-border bg-surface/50 hover:border-accent/30 hover:bg-surface transition-all">
                    <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center mb-4 text-accent group-hover:bg-accent/20 transition-colors">
                      <Icon />
                    </div>
                    <h3 className="font-semibold mb-2">{t[`h_${key}_title`]}</h3>
                    <p className="text-sm text-muted leading-relaxed">{t[`h_${key}_desc`]}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section className="py-24 px-6">
          <div className="max-w-2xl mx-auto text-center">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
              {t.cta_title}
            </h2>
            <p className="text-muted text-lg mb-8">{t.cta_desc}</p>
            <div className="inline-flex items-center gap-3 px-5 py-3 rounded-lg bg-surface border border-border font-mono text-sm mb-4">
              <span className="text-accent">$</span>
              {t.cta_install}
            </div>
            <p className="text-sm text-muted">
              or download a <a href={`${GITHUB}/releases`} className="text-accent hover:text-fg transition-colors underline underline-offset-2" target="_blank" rel="noopener">prebuilt binary</a> from GitHub Releases
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-border py-8 px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-muted">
          <div className="flex items-center gap-1">
            {t.footer_built}{" "}
            <a href={MASTODON} className="text-fg hover:text-accent transition-colors" target="_blank" rel="noopener me">
              @codecolorist
            </a>
          </div>
          <div className="flex items-center gap-6">
            <a href={GITHUB} className="hover:text-fg transition-colors" target="_blank" rel="noopener">GitHub</a>
            <a href={SPONSOR} className="hover:text-fg transition-colors" target="_blank" rel="noopener">{t.nav_sponsor}</a>
            <span>{t.footer_license}</span>
          </div>
        </div>
      </footer>
    </>
  );
}

function Arrow() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Hook() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 9a3 3 0 1 0-6 0v10a3 3 0 0 1-6 0V9" />
    </svg>
  );
}

function Cpu() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <path d="M15 2v2M15 20v2M2 15h2M20 15h2M9 2v2M9 20v2M2 9h2M20 9h2" />
    </svg>
  );
}

function Layers() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.84Z" />
      <path d="m2 12 8.58 3.91a2 2 0 0 0 1.66 0L21 12" />
      <path d="m2 17 8.58 3.91a2 2 0 0 0 1.66 0L21 17" />
    </svg>
  );
}

function Globe() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
      <path d="M2 12h20" />
    </svg>
  );
}

function Scale() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z" />
      <path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z" />
      <path d="M7 21h10" />
      <path d="M12 3v18" />
      <path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}
