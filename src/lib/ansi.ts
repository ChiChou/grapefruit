const ANSI_RE = /\x1b\[([0-9;]*)m/g;

const BASIC_COLORS: Record<number, string> = {
  30: "#1e1e1e", 31: "#cd3131", 32: "#0dbc79", 33: "#e5e510",
  34: "#2472c8", 35: "#bc3fbc", 36: "#11a8cd", 37: "#e5e5e5",
  90: "#666666", 91: "#f14c4c", 92: "#23d18b", 93: "#f5f543",
  94: "#3b8eea", 95: "#d670d6", 96: "#29b8db", 97: "#ffffff",
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function ansiToHtml(input: string): string {
  let result = "";
  let lastIndex = 0;
  let openSpan = false;

  for (const match of input.matchAll(ANSI_RE)) {
    result += escapeHtml(input.slice(lastIndex, match.index));
    lastIndex = match.index! + match[0].length;

    const codes = match[1].split(";").map(Number);
    if (openSpan) {
      result += "</span>";
      openSpan = false;
    }

    for (let i = 0; i < codes.length; i++) {
      const code = codes[i];
      if (code === 0 || code === 39) continue;

      // 24-bit: 38;2;r;g;b
      if (code === 38 && codes[i + 1] === 2 && i + 4 < codes.length) {
        const r = codes[i + 2], g = codes[i + 3], b = codes[i + 4];
        result += `<span style="color:rgb(${r},${g},${b})">`;
        openSpan = true;
        i += 4;
        continue;
      }

      // 256-color: 38;5;n
      if (code === 38 && codes[i + 1] === 5 && i + 2 < codes.length) {
        const n = codes[i + 2];
        const hex = color256(n);
        result += `<span style="color:${hex}">`;
        openSpan = true;
        i += 2;
        continue;
      }

      // Basic foreground
      if (BASIC_COLORS[code]) {
        result += `<span style="color:${BASIC_COLORS[code]}">`;
        openSpan = true;
        continue;
      }

      // Bold
      if (code === 1) {
        result += `<span style="font-weight:bold">`;
        openSpan = true;
        continue;
      }
    }
  }

  result += escapeHtml(input.slice(lastIndex));
  if (openSpan) result += "</span>";
  return result;
}

function color256(n: number): string {
  if (n < 16) {
    const basic = [
      "#000", "#c00", "#0c0", "#cc0", "#00c", "#c0c", "#0cc", "#ccc",
      "#666", "#f00", "#0f0", "#ff0", "#00f", "#f0f", "#0ff", "#fff",
    ];
    return basic[n];
  }
  if (n < 232) {
    const i = n - 16;
    const r = Math.floor(i / 36) * 51;
    const g = (Math.floor(i / 6) % 6) * 51;
    const b = (i % 6) * 51;
    return `rgb(${r},${g},${b})`;
  }
  const gray = (n - 232) * 10 + 8;
  return `rgb(${gray},${gray},${gray})`;
}
