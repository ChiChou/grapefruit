/**
 * Strip decorative formatting from disassembly before sending to LLM.
 */

export function r2(text: string): string {
  return text
    .replace(/^[/\\|;]\s*$/gm, "")
    .replace(/^[|/\\]\s+/gm, "")
    .replace(/^\s*;--\s*.*$/gm, "")
    .replace(/\s+;.*$/gm, "")
    .replace(/^0x[0-9a-f]+\s+/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function hermes(text: string): string {
  return text
    .replace(/^\s*@\s*offset\s+0x[0-9a-f]+\s*$/gm, "")
    .replace(/^Bytecode listing \(asm\):\s*$/gm, "")
    .replace(/^0x[0-9a-f]+:\s*/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
