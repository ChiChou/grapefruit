import { siDiscord } from "simple-icons";

export function DiscordButton({ href }: { href: string }) {
  return (
    <a
      href={href}
      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#5865F2]/30 bg-[#5865F2]/10 text-sm font-medium text-[#8b9aff] hover:bg-[#5865F2]/20 hover:border-[#5865F2]/50 transition-colors"
      target="_blank"
      rel="noopener"
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
        <path d={siDiscord.path} />
      </svg>
      Discord
    </a>
  );
}
