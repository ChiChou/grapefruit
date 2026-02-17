import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useTheme } from "@/components/providers/ThemeProvider";

interface TerminalProps {
  onTerminalReady?: (terminal: XTerm) => void;
}

export function Terminal({ onTerminalReady }: TerminalProps) {
  const { theme } = useTheme();
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);

  useEffect(() => {
    if (!terminalRef.current) return;

    const term = new XTerm({
      convertEol: true,
      theme: {
        background: theme === "dark" ? "#000000" : "#ffffff",
        foreground: theme === "dark" ? "#d0d0d0" : "#333333",
      },
      fontSize: 12,
      fontFamily: "monospace",
      rows: 24,
      cols: 80,
    });

    term.open(terminalRef.current);
    xtermRef.current = term;

    if (onTerminalReady) {
      onTerminalReady(term);
    }

    const resizeTerminal = () => {
      const dims = terminalRef.current?.getBoundingClientRect();
      if (dims) {
        const cols = Math.floor(dims.width / 8);
        const rows = Math.floor(dims.height / 16);
        if (cols > 0 && rows > 0) {
          term.resize(cols, rows);
        }
      }
    };

    const observer = new ResizeObserver(resizeTerminal);
    observer.observe(terminalRef.current);

    resizeTerminal();

    return () => {
      observer.disconnect();
      term.dispose();
    };
  }, [onTerminalReady, theme]);

  useEffect(() => {
    if (xtermRef.current) {
      xtermRef.current.options.theme = {
        background: theme === "dark" ? "#000000" : "#ffffff",
        foreground: theme === "dark" ? "#d0d0d0" : "#333333",
      };
    }
  }, [theme]);

  return <div ref={terminalRef} className="h-full w-full" />;
}
