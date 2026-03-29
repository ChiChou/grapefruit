// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[([0-9;]*)m/g;

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function isBasicFg(code: number): boolean {
  return (code >= 30 && code <= 37) || (code >= 90 && code <= 97);
}

export function toHtml(input: string): string {
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

      // 24-bit: 38;2;r;g;b (fallback for non-themed output)
      if (code === 38 && codes[i + 1] === 2 && i + 4 < codes.length) {
        const r = codes[i + 2], g = codes[i + 3], b = codes[i + 4];
        result += `<span style="color:rgb(${r},${g},${b})">`;
        openSpan = true;
        i += 4;
        continue;
      }

      // 256-color: 38;5;n (fallback for non-themed output)
      if (code === 38 && codes[i + 1] === 5 && i + 2 < codes.length) {
        const n = codes[i + 2];
        const hex = color256(n);
        result += `<span style="color:${hex}">`;
        openSpan = true;
        i += 2;
        continue;
      }

      // Basic foreground → CSS class (themed via --r2-c* variables)
      if (isBasicFg(code)) {
        result += `<span class="r2-c${code}">`;
        openSpan = true;
        continue;
      }

      // Bold
      if (code === 1) {
        result += `<span class="r2-bold">`;
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
