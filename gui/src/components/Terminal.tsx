import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";

interface TerminalProps {
  onTerminalReady?: (terminal: XTerm) => void;
}

export function Terminal({ onTerminalReady }: TerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);

  useEffect(() => {
    if (!terminalRef.current) return;

    const term = new XTerm({
      convertEol: true,
      theme: {
        background: "#000000",
        foreground: "#ffffff",
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

    const handleResize = () => {
      const dims = terminalRef.current?.getBoundingClientRect();
      if (dims) {
        const cols = Math.floor(dims.width / 8);
        const rows = Math.floor(dims.height / 16);
        if (cols > 0 && rows > 0) {
          term.resize(cols, rows);
        }
      }
    };

    handleResize();
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      term.dispose();
    };
  }, [onTerminalReady]);

  return <div ref={terminalRef} className="h-full w-full" />;
}
