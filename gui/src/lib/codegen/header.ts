// const PROPERTY_ATTRS = "TRC&WNOD" as const;
type Property = Record<string, string>;

export interface Ivar {
  name: string;
  offset: number;
  type: string;
}

export interface Method {
  name: string;
  impl: string;
  types: string;
}

export interface ClassDumpInfo {
  name: string;
  protocols: string[];
  methods: Method[];
  ownMethods: string[]; // lookup in methods
  proto: string[]; // superclass chain
  ivars: Ivar[];
  module: string;
  properties: Record<string, Property>;
}

// Type definitions for the parser result
interface MethodSignature {
  args: string[];
  ret: string;
}

export class ObjCTypeParser {
  private encoding: string;
  private index: number;

  private static readonly BASIC_TYPES: Record<string, string> = {
    c: "char",
    i: "int",
    s: "short",
    l: "long",
    q: "long long",
    C: "unsigned char",
    I: "unsigned int",
    S: "unsigned short",
    L: "unsigned long",
    Q: "unsigned long long",
    f: "float",
    d: "double",
    B: "BOOL",
    v: "void",
    "*": "char *",
    "#": "Class",
    ":": "SEL",
    "?": "unknown",
  };

  constructor(encoding: string) {
    this.encoding = encoding;
    this.index = 0;
  }

  /**
   * Main entry point to parse a full method signature (e.g., "v24@0:8@16")
   */
  public static parse(signature: string): MethodSignature {
    const parser = new ObjCTypeParser(signature);
    return parser.parseMethod();
  }

  /**
   * Parses a single type encoding string (e.g. "^i")
   */
  public static parseType(typeEncoding: string): string {
    const parser = new ObjCTypeParser(typeEncoding);
    return parser.parseNextType();
  }

  private peek(): string {
    return this.encoding[this.index] || "";
  }

  private advance(count: number = 1): void {
    this.index += count;
  }

  private consumeNumbers(): void {
    while (/[0-9]/.test(this.peek())) {
      this.advance();
    }
  }

  private parseMethod(): MethodSignature {
    // 1. Parse Return Type
    const ret = this.parseNextType();
    this.consumeNumbers(); // Stack size

    const args: string[] = [];

    // 2. Parse Arguments
    while (this.index < this.encoding.length) {
      const argType = this.parseNextType();
      args.push(argType);
      this.consumeNumbers(); // Argument offset
    }

    return { ret, args };
  }

  private parseNextType(): string {
    const char = this.peek();
    this.advance();

    // 1. Handle Modifiers (recursive prefix)
    // r = const, n = in, N = inout, o = out, O = bycopy, R = byref, V = oneway
    if (["r", "n", "N", "o", "O", "R", "V"].includes(char)) {
      const modifierMap: Record<string, string> = { r: "const", R: "byref" }; // Simplified
      const mod = modifierMap[char] ? modifierMap[char] + " " : "";
      return mod + this.parseNextType();
    }

    // 2. Handle Basic Types
    if (ObjCTypeParser.BASIC_TYPES[char]) {
      return ObjCTypeParser.BASIC_TYPES[char];
    }

    switch (char) {
      case "^": {
        // Pointer
        // Special case: ^v is void*, ^@ is NSError** (usually)
        const inner = this.parseNextType();
        if (inner === "void") return "void *";
        return `${inner} *`;
      }

      case "@": // Object
        return this.parseObjectType();

      case "[": // Array
        return this.parseArrayType();

      case "{": // Struct
        return this.parseStructureType("{", "}");

      case "(": // Union
        return this.parseStructureType("(", ")");

      case "b": // Bitfield
        this.consumeNumbers(); // skip width
        return "int"; // Simplified for headers

      default:
        return "id"; // Fallback
    }
  }

  private parseObjectType(): string {
    // @ -> id
    // @"ClassName" -> ClassName *
    // @? -> block

    if (this.peek() === '"') {
      this.advance(); // skip "
      let className = "";
      while (this.peek() !== '"' && this.index < this.encoding.length) {
        // Handle protocols <Proto> in name
        className += this.peek();
        this.advance();
      }
      this.advance(); // skip closing "

      // Clean up protocol syntax for header if needed, strictly it's Class<Proto> *
      return `${className} *`;
    }

    if (this.peek() === "?") {
      this.advance();
      // Handle block signature if present: @?<v@?>
      if (this.peek() === "<") {
        this.skipBalanced("<", ">");
        // For simplicity in this port, returning generic block.
        // A full block parser would recurse here similar to parseMethod.
        return "void (^)(void)";
      }
      return "id /* block */";
    }

    return "id";
  }

  private parseArrayType(): string {
    // [12^f] -> float*[12]
    // Extract size
    let sizeStr = "";
    while (/[0-9]/.test(this.peek())) {
      sizeStr += this.peek();
      this.advance();
    }

    const innerType = this.parseNextType();

    // Skip closing ]
    if (this.peek() === "]") this.advance();

    return `${innerType}[${sizeStr}]`;
  }

  private parseStructureType(open: string, close: string): string {
    // {name=T...}
    // {_struct=sqQ}

    if (this.peek() !== open) return "unknown"; // Fallback

    let name = "";
    // Read name until = or close
    while (
      this.peek() !== "=" &&
      this.peek() !== close &&
      this.index < this.encoding.length
    ) {
      name += this.peek();
      this.advance();
    }

    if (this.peek() === "=") {
      this.advance(); // Skip =
      // We need to skip the internal types to advance the cursor,
      // but we don't necessarily display them in a C-style header "struct Name *"
      // unless we are defining the struct.
      while (this.peek() !== close && this.index < this.encoding.length) {
        this.parseNextType();
      }
    }

    if (this.peek() === close) this.advance();

    if (name === "?") return "struct /* anonymous */";
    return `struct ${name}`;
  }

  private skipBalanced(open: string, close: string) {
    let depth = 1;
    this.advance();
    while (depth > 0 && this.index < this.encoding.length) {
      const c = this.peek();
      if (c === open) depth++;
      else if (c === close) depth--;
      this.advance();
    }
  }
}

export function header(info: ClassDumpInfo): string {
  const lines: string[] = [];

  // 1. Interface Declaration
  const superC =
    info.properties["superclass"] && info.proto.length
      ? "NSObject"
      : info.proto[0] || "NSObject"; // Inference
  let decl = `@interface ${info.name} : ${superC}`;
  if (info.protocols && info.protocols.length > 0) {
    decl += ` <${info.protocols.join(", ")}>`;
  }
  lines.push(decl);
  lines.push("");

  // 2. Properties
  const sortedProps = Object.keys(info.properties).sort();
  for (const propName of sortedProps) {
    const attrs = info.properties[propName];
    const attrStrings: string[] = [];
    const attrLookup: Record<string, string> = {
      R: "readonly",
      C: "copy",
      "&": "strong",
      W: "weak",
      N: "nonatomic",
    };

    for (const key in attrLookup) {
      if (attrs[key]) attrStrings.push(attrLookup[key]);
    }

    if (attrs["D"]) continue; // @dynamic, usually skip generating property or mark it

    // Parse Type
    const typeStr = ObjCTypeParser.parseType(attrs.T);

    // Formatting hack: if type is "Object *", property name goes after *.
    // If type is "id", property name goes after space.

    const attrBlock =
      attrStrings.length > 0 ? `(${attrStrings.join(", ")}) ` : "";
    lines.push(`@property ${attrBlock}${typeStr} ${propName};`);
  }

  lines.push("");

  // 3. Methods
  const sortedMethods = info.methods.sort((a, b) =>
    a.name.localeCompare(b.name),
  );

  for (const meth of sortedMethods) {
    const sel = meth.name;
    const signature = meth.types;

    const cleanSel = sel.replace(/^[-+] /, "");
    const methodSymbol = sel.startsWith("+") ? "+" : "-";

    const parsed = ObjCTypeParser.parse(signature);

    // parsed.args includes [self, _cmd, arg1, arg2...]
    // We skip index 0 (self) and 1 (_cmd)
    const realArgs = parsed.args.slice(2);

    // Split selector by ':' to map arguments
    const selParts = cleanSel.split(":").filter((s) => s.length > 0);

    // Reconstruct Method definition
    let methodLine = `${methodSymbol} (${parsed.ret})`;

    if (realArgs.length === 0) {
      methodLine += `${cleanSel}`;
    } else {
      // Interleave selector parts and arguments
      // sel: "dataWithBytes:length:" -> ["dataWithBytes", "length"]
      // args: ["const void *", "unsigned long long"]

      selParts.forEach((part, i) => {
        const argType = realArgs[i] || "id"; // Fallback
        // Standard arg naming: arg1, arg2...
        const argName = `arg${i + 1}`;
        methodLine += `${part}:(${argType})${argName} `;
      });
    }

    lines.push(methodLine.trim() + ";");
  }

  lines.push("");
  lines.push("@end");

  return lines.join("\n");
}
