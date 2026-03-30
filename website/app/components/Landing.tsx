import Image from "next/image";
import Link from "next/link";
import { Globe, Layers, Wand, Anchor, Search, Cpu, ArrowRight } from "lucide-react";
import { CopyInstall } from "./CopyInstall";
import { DiscordButton } from "./DiscordButton";
import { PlatformScreenshot } from "./PlatformScreenshot";
import { StarButton } from "./StarButton";
import { ThemeScreenshot } from "./ThemeScreenshot";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

type Strings = Record<string, string>;

const GITHUB = "https://github.com/chichou/grapefruit";
const MASTODON = "https://infosec.exchange/@codecolorist";
const SPONSOR = "https://github.com/sponsors/ChiChou";
const DISCORD = "https://discord.com/invite/pwutZNx";

const whyIcons = [Globe, Layers, Wand] as const;
const highlightIcons = [Anchor, Search, Cpu] as const;

export function Landing({ t, langHref }: { t: Strings; langHref: string }) {
  return (
    <>
      <header className="fixed top-0 inset-x-0 z-50 border-b border-border/50 bg-bg/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto flex items-center justify-between h-14 px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2 shrink-0">
            <Image src={`${base}/logo.svg`} alt="Grapefruit" width={24} height={24} />
            <span className="font-semibold tracking-tight text-sm hidden sm:inline">Grapefruit</span>
          </Link>
          <nav className="flex items-center gap-3 sm:gap-6 text-sm text-muted">
            <Link href="/docs" className="hover:text-fg transition-colors">
              {t.nav_docs}
            </Link>
            <a href={GITHUB} className="hover:text-fg transition-colors" target="_blank" rel="noreferrer">
              {t.nav_github}
            </a>
            <a href={SPONSOR} className="hover:text-fg transition-colors inline-flex items-center gap-1" target="_blank" rel="noreferrer">
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
        <section className="relative pt-28 pb-20 px-6 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(255,167,69,0.08),transparent_60%)]" />
          <div className="relative max-w-5xl mx-auto text-center">
            <div className="mb-6 flex items-center justify-center gap-3">
              <StarButton href={GITHUB} />
              <DiscordButton href={DISCORD} />
            </div>
            <h1 className="text-5xl sm:text-7xl font-bold tracking-tight leading-[1.08] mb-5">
              {t.hero_title}
            </h1>
            <p className="text-base sm:text-xl text-muted/80 max-w-2xl mx-auto mb-8 leading-relaxed">{t.hero_desc}</p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-4">
              <div className="flex items-center gap-3">
                <a href={GITHUB} className="inline-flex items-center gap-2 px-6 py-3 bg-fg text-bg rounded-lg font-medium text-sm hover:bg-fg/90 transition-colors">
                  {t.hero_cta}
                  <ArrowRight size={16} />
                </a>
                <Link href={langHref === "/" ? "/cn/docs" : "/docs"} className="inline-flex items-center gap-2 px-6 py-3 border border-border rounded-lg font-medium text-sm text-muted hover:text-fg hover:border-fg/20 transition-colors">
                  {t.hero_cta_docs}
                </Link>
              </div>
              <CopyInstall cmd={t.cta_install} />
            </div>

            <PlatformScreenshot />
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
                      <Icon size={20} />
                    </div>
                    <h3 className="font-semibold mb-2">{t[`h_${key}_title`]}</h3>
                    <p className="text-sm text-muted leading-relaxed">{t[`h_${key}_desc`]}</p>
                  </div>
                );
              })}
            </div>
            <div className="mt-10 text-center">
              <Link href={langHref === "/" ? "/cn/docs" : "/docs"} className="inline-flex items-center gap-2 text-sm text-muted hover:text-accent transition-colors group">
                {t.cta_all_features}
                <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
              </Link>
            </div>
          </div>
        </section>

        <section className="py-24 px-6 border-t border-border">
          <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-10">
            <div>
              <h3 className="text-2xl font-bold tracking-tight mb-2">{t.feat_hermes_title}</h3>
              <p className="text-sm text-muted leading-relaxed mb-5">{t.feat_hermes_desc}</p>
              <div className="rounded-xl overflow-hidden">
                <Image src={`${base}/hermes.webp`} alt="Hermes bytecode viewer" width={1374} height={1025} className="w-full opacity-75 hover:opacity-100 transition-opacity" />
              </div>
            </div>
            <div>
              <h3 className="text-2xl font-bold tracking-tight mb-2">{t.feat_r2_title}</h3>
              <p className="text-sm text-muted leading-relaxed mb-5">{t.feat_r2_desc}</p>
              <div className="rounded-xl overflow-hidden">
                <Image src={`${base}/radare2.webp`} alt="Radare2 split view with CFG" width={1374} height={1025} className="w-full opacity-75 hover:opacity-100 transition-opacity" />
              </div>
            </div>
          </div>
        </section>

        <section className="py-24 px-6 border-t border-border">
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
                      <Icon size={20} />
                    </div>
                    <h3 className="font-semibold mb-2">{t[`why_${key}_title`]}</h3>
                    <p className="text-sm text-muted leading-relaxed">{t[`why_${key}_desc`]}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <ThemeScreenshot title={t.theme_title} desc={t.theme_desc} />

        <section className="py-24 px-6 border-t border-border">
          <div className="max-w-2xl mx-auto text-center">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
              {t.cta_title}
            </h2>
            <p className="text-muted mb-8">{t.cta_desc}</p>
            <CopyInstall cmd={t.cta_install} />
          </div>
        </section>
      </main>

      <footer className="border-t border-border py-8 px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-muted">
          <div className="flex items-center gap-1">
            {t.footer_built}{" "}
            <a href={MASTODON} className="text-fg hover:text-accent transition-colors" target="_blank" rel="noreferrer me">
              @codecolorist
            </a>
          </div>
          <div className="flex items-center gap-6">
            <a href={GITHUB} className="hover:text-fg transition-colors" target="_blank" rel="noreferrer">GitHub</a>
            <a href={SPONSOR} className="hover:text-fg transition-colors" target="_blank" rel="noreferrer">{t.nav_sponsor}</a>
            <span>{t.footer_license}</span>
          </div>
        </div>
      </footer>
    </>
  );
}

