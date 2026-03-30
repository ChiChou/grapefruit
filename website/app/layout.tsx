import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { LanguageProvider } from "./context/LanguageContext";
import { ThemeProvider } from "./context/ThemeContext";
import "./globals.css";

const sans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const mono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

export const metadata: Metadata = {
  ...(process.env.NEXT_PUBLIC_BASE_URL && { metadataBase: new URL(process.env.NEXT_PUBLIC_BASE_URL) }),
  title: "Grapefruit - Open-Source Mobile Security Testing Suite",
  description:
    "Instrumentation, data inspection, and decompilation for iOS & Android — all in your browser.",
  icons: {
    icon: `${base}/logo.svg`,
  },
  openGraph: {
    images: [{ url: "/opengraph.webp", alt: "Grapefruit - Open-Source Mobile Security Testing Suite" }],
  },
  twitter: {
    card: "summary_large_image",
    images: [{ url: "/screenshot-fruity.webp", alt: "Grapefruit - Open-Source Mobile Security Testing Suite" }],
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${sans.variable} ${mono.variable} antialiased`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: `try{if(localStorage.getItem("theme")==="light")document.documentElement.classList.add("light")}catch(e){}` }} />
      </head>
      <body className="min-h-dvh flex flex-col bg-bg text-fg">
        <ThemeProvider><LanguageProvider>{children}</LanguageProvider></ThemeProvider>
      </body>
    </html>
  );
}
