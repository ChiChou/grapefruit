import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { LanguageProvider } from "./context/LanguageContext";
import "./globals.css";

const sans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const mono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Grapefruit - Mobile Security Research Toolkit",
  description:
    "Instrument, analyze, and decompile mobile apps with Frida, radare2, and AI. iOS & Android.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${sans.variable} ${mono.variable} antialiased`}
    >
      <body className="min-h-dvh flex flex-col bg-bg text-fg">
        <LanguageProvider>{children}</LanguageProvider>
      </body>
    </html>
  );
}
