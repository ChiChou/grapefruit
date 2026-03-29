import type { HBCFunction, HBCString } from "./use-hbc";

export interface Line {
  type: "instruction" | "comment" | "blank" | "separator";
  address?: string;
  opcode?: string;
  operands?: string[];
  /** Resolved annotations per operand index */
  annotations?: Map<number, string>;
  /** Raw text for comment/separator lines */
  text?: string;
}

export interface Jump {
  from: number; // line index
  to: number;   // line index
  column: number; // assigned gutter column for nesting
}

/** Parse a single instruction line: "0xADDR: opcode op1, op2, ..." */
function parseInstruction(line: string): Line | null {
  // Find ": " separator between address and the rest
  const colonIdx = line.indexOf(": ");
  if (colonIdx < 0) return null;

  const address = normAddr(line.slice(0, colonIdx).trim());
  const rest = line.slice(colonIdx + 2);

  // First word is opcode, remainder is operands
  const spaceIdx = rest.indexOf(" ");
  if (spaceIdx < 0) {
    return { type: "instruction", address, opcode: rest, operands: [] };
  }

  const opcode = rest.slice(0, spaceIdx);
  const operandStr = rest.slice(spaceIdx + 1).trim();

  // Split operands by ", "
  const operands = operandStr ? operandStr.split(", ") : [];

  return { type: "instruction", address, opcode, operands };
}

/** Normalize hex address: strip leading zeros after 0x */
function normAddr(addr: string): string {
  if (!addr.startsWith("0x")) return addr;
  const stripped = addr.slice(2).replace(/^0+/, "") || "0";
  return "0x" + stripped;
}

/** Parse raw disassembly text into structured lines. */
export function parse(raw: string): Line[] {
  const lines: Line[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();

    if (!trimmed) {
      lines.push({ type: "blank" });
      continue;
    }

    // Filter out r2hermes separators and headers
    if (trimmed.startsWith("=") || trimmed.startsWith("@") || trimmed.startsWith("Bytecode")) {
      continue;
    }

    if (trimmed.startsWith(";")) {
      lines.push({ type: "comment", text: trimmed });
      continue;
    }

    const inst = parseInstruction(trimmed);
    if (inst) {
      lines.push(inst);
    } else {
      // Fallback: treat as comment
      lines.push({ type: "comment", text: trimmed });
    }
  }
  return lines;
}

/** Build hex offset → string lookup from string table (disassembler outputs file offsets). */
function buildOffsetMap(strings: HBCString[]): Map<string, HBCString> {
  const map = new Map<string, HBCString>();
  for (const s of strings) {
    map.set("0x" + s.offset.toString(16), s);
  }
  return map;
}

function buildFuncByOffset(functions: HBCFunction[]): Map<number, HBCFunction> {
  const map = new Map<number, HBCFunction>();
  for (const f of functions) map.set(f.offset, f);
  return map;
}

function truncStr(s: string, max = 40): string {
  return s.length > max ? s.slice(0, max) + "..." : s;
}

/** Resolve string/identifier/function references in operands. */
export function resolve(
  lines: Line[],
  strings: HBCString[],
  functions: HBCFunction[],
): void {
  const offsetMap = buildOffsetMap(strings);
  const funcByOffset = buildFuncByOffset(functions);

  for (const line of lines) {
    if (line.type !== "instruction" || !line.operands || !line.opcode) continue;

    const annotations = new Map<number, string>();
    const op = line.opcode;
    const isClosure = op === "create_closure" || op === "create_closure_long_index";

    for (let i = 0; i < line.operands.length; i++) {
      const operand = line.operands[i];
      if (!operand.startsWith("0x")) continue;

      // Try function offset (for create_closure)
      if (isClosure) {
        const offset = parseInt(operand, 16);
        const func = funcByOffset.get(offset);
        if (func) {
          annotations.set(i, `→ ${func.name}()`);
          continue;
        }
      }

      // Try string offset
      const str = offsetMap.get(normAddr(operand));
      if (str) {
        const display = str.kind === "string"
          ? JSON.stringify(truncStr(str.value))
          : truncStr(str.value);
        annotations.set(i, display);
      }
    }

    if (annotations.size > 0) {
      line.annotations = annotations;
    }
  }
}

/** Identify branch instructions and compute jump edges. */
export function findJumps(lines: Line[]): Jump[] {
  // Build address → line index map
  const addrToIdx = new Map<string, number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.type === "instruction" && line.address) {
      addrToIdx.set(line.address, i);
    }
  }

  const jumps: Jump[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.type !== "instruction" || !line.opcode || !line.operands) continue;

    // Branch opcodes start with "j"
    if (!line.opcode.startsWith("j")) continue;

    // Check all 0x operands — target can be at any position
    for (const op of line.operands) {
      if (!op.startsWith("0x")) continue;
      const targetIdx = addrToIdx.get(normAddr(op));
      if (targetIdx !== undefined && targetIdx !== i) {
        jumps.push({ from: i, to: targetIdx, column: 0 });
        break;
      }
    }
  }

  // Assign columns to avoid overlapping arrows
  assignColumns(jumps);
  return jumps;
}

/** Assign non-overlapping columns to jump arrows. */
function assignColumns(jumps: Jump[]): void {
  // Sort by span length (smaller spans get inner columns)
  const sorted = [...jumps].sort(
    (a, b) => Math.abs(a.to - a.from) - Math.abs(b.to - b.from),
  );

  for (const jump of sorted) {
    const minRow = Math.min(jump.from, jump.to);
    const maxRow = Math.max(jump.from, jump.to);

    // Find first column not used by any overlapping jump
    let col = 0;
    outer: while (col < 10) {
      for (const other of jumps) {
        if (other === jump || other.column !== col) continue;
        const oMin = Math.min(other.from, other.to);
        const oMax = Math.max(other.from, other.to);
        if (minRow <= oMax && maxRow >= oMin) {
          col++;
          continue outer;
        }
      }
      break;
    }
    jump.column = col;
  }
}

/**
 * Build an optimized LLM prompt from parsed disassembly.
 * - Only includes addresses for branch targets
 * - Inlines resolved string/identifier values
 * - Includes function context
 */
export function buildLlmContext(
  lines: Line[],
  funcName: string,
  paramCount: number | undefined,
  strings: HBCString[],
  functions: HBCFunction[],
): string {
  resolve(lines, strings, functions);

  // Pass 1: build address → line index map
  const addrToIdx = new Map<string, number>();
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.type === "instruction" && l.address) addrToIdx.set(l.address, i);
  }

  // Pass 2: collect all jump target addresses from branch operands
  const targetAddrs = new Set<string>();
  for (const line of lines) {
    if (line.type !== "instruction" || !line.opcode?.startsWith("j")) continue;
    for (const op of line.operands ?? []) {
      if (!op.startsWith("0x")) continue;
      const norm = normAddr(op);
      if (addrToIdx.has(norm)) targetAddrs.add(norm);
    }
  }

  // Pass 3: emit
  const parts: string[] = [
    "Decompile the following Hermes bytecode into clean, idiomatic JavaScript.",
    "Reconstruct variable names from context, simplify control flow, recover React/RN patterns.",
    "Output ONLY raw source code. No markdown, no code fences, no explanations.",
    "",
    `Function: ${funcName}`,
  ];
  if (paramCount !== undefined) parts.push(`Parameters: ${paramCount}`);
  parts.push("");

  for (const line of lines) {
    if (line.type === "blank" || line.type === "separator") continue;

    if (line.type === "comment") {
      if (line.text?.startsWith(";")) parts.push(line.text);
      continue;
    }

    if (line.type !== "instruction" || !line.opcode) continue;

    // Insert label before branch targets
    if (targetAddrs.has(line.address!)) {
      parts.push(`${line.address}:`);
    }

    // Build operand string with annotations
    const ops = (line.operands ?? []).map((op, i) => {
      const ann = line.annotations?.get(i);
      return ann ? `${op} /* ${ann} */` : op;
    });

    parts.push(`  ${line.opcode} ${ops.join(", ")}`);
  }

  return parts.join("\n");
}
