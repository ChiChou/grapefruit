export function parse(signature: string) {
  let index = 0;
  const tokens = [];

  const isDigit = (char: string) => /^\d$/.test(char);

  // ---------------------------------------------------------
  // 1. THE SCANNER
  // Ported from +[CDTypeParser endOfTypeEncoding:]
  // ---------------------------------------------------------
  function findTypeEnd(str: string, idx: number) {
    // Safety check
    if (idx >= str.length) return idx;

    const char = str[idx];
    idx++; // consume first char

    switch (char) {
      // Primitive types and simple modifiers (1 char length)
      case "c":
      case "i":
      case "s":
      case "l":
      case "q":
      case "C":
      case "I":
      case "S":
      case "L":
      case "Q":
      case "f":
      case "d":
      case "B":
      case "v":
      case "*":
      case "#":
      case ":":
      case " ":
      case "?":
        return idx;

      // Pointers and modifiers that precede a type
      case "^": // pointer
      case "r": // const
      case "n": // in
      case "N": // inout
      case "o": // out
      case "O": // bycopy
      case "R": // byref
      case "V": // oneway
        return findTypeEnd(str, idx);

      // Arrays [type] or [count type]
      case "[": {
        let openTokens = 1;
        while (openTokens > 0 && idx < str.length) {
          const next = str[idx++];
          if (next === "[") openTokens++;
          if (next === "]") openTokens--;
        }
        return idx;
      }

      // Structs {name=type...}
      case "{": {
        let openTokens = 1;
        while (openTokens > 0 && idx < str.length) {
          const next = str[idx++];
          if (next === "{") openTokens++;
          if (next === "}") openTokens--;
        }
        return idx;
      }

      // Unions (name=type...)
      case "(": {
        let openTokens = 1;
        while (openTokens > 0 && idx < str.length) {
          const next = str[idx++];
          if (next === "(") openTokens++;
          if (next === ")") openTokens--;
        }
        return idx;
      }

      // Objects @, @"ClassName" or Blocks @?
      case "@": {
        if (idx < str.length) {
          if (str[idx] === '"') {
            // @"ClassName"
            idx++; // skip opening quote
            while (idx < str.length && str[idx] !== '"') {
              idx++;
            }
            if (idx < str.length) idx++; // skip closing quote
          } else if (str[idx] === "?") {
            // @? (Block) -> recurses into block signature <...>
            idx++;
            if (idx < str.length && str[idx] === "<") {
              let openTokens = 1;
              idx++; // skip <
              while (openTokens > 0 && idx < str.length) {
                const next = str[idx++];
                if (next === "<") openTokens++;
                if (next === ">") openTokens--;
              }
            }
          }
        }
        return idx;
      }

      // Bitfields b123
      case "b": {
        while (idx < str.length && isDigit(str[idx])) {
          idx++;
        }
        return idx;
      }

      default:
        return idx;
    }
  }

  // ---------------------------------------------------------
  // 2. THE DECODER
  // Simplifies the raw encoding string into readable names
  // ---------------------------------------------------------
  function decodeType(typeStr: string): string {
    if (!typeStr) return "void";

    const prefix = typeStr[0];

    // --- Modifiers ---
    // Recursively strip const/in/out/etc modifiers
    if (["r", "n", "N", "o", "O", "R", "V"].includes(prefix)) {
      return decodeType(typeStr.substring(1));
    }

    // --- Pointers ---
    if (prefix === "^") {
      // Special case: ^v is void*
      if (typeStr === "^v") return "void*";
      // Special case: ^@ is usually NSError** (pointer to object)
      if (typeStr === "^@") return "id*"; // Or generic pointer

      const inner = decodeType(typeStr.substring(1));
      // If inner is unknown (like a struct), strict parsing says keep it unknown,
      // but for pointers usually we just append *.
      if (inner === "unknown") return "void*";
      return `${inner}*`;
    }

    // --- Arrays ---
    if (prefix === "[") {
      // Format: [10i] or [i]
      // Extract content between [ and ]
      const content = typeStr.substring(1, typeStr.length - 1);

      // Separate numbers from type. Example "5i" -> count=5, type=i
      let typeStart = 0;
      while (typeStart < content.length && isDigit(content[typeStart])) {
        typeStart++;
      }

      const remaining = content.substring(typeStart);
      const innerType = decodeType(remaining);

      if (innerType === "unknown") return "unknown";
      return `${innerType}[]`;
    }

    // --- Structures / Unions ---
    if (prefix === "{" || prefix === "(") {
      return "unknown";
    }

    // --- Objects ---
    if (prefix === "@") {
      if (typeStr === "@?") return "block"; // Block
      if (typeStr.startsWith('@"')) {
        // Extract Class Name: @"NSString" -> NSString*
        return typeStr.substring(2, typeStr.length - 1) + "*";
      }
      return "id"; // Plain id
    }

    // --- Primitives ---
    switch (prefix) {
      case "c":
        return "char";
      case "i":
        return "int";
      case "s":
        return "short";
      case "l":
        return "long";
      case "q":
        return "long long";
      case "C":
        return "unsigned char";
      case "I":
        return "unsigned int";
      case "S":
        return "unsigned short";
      case "L":
        return "unsigned long";
      case "Q":
        return "unsigned long long";
      case "f":
        return "float";
      case "d":
        return "double";
      case "B":
        return "BOOL";
      case "v":
        return "void";
      case "*":
        return "char*";
      case ":":
        return "SEL";
      case "#":
        return "Class";
      case "?":
        return "unknown"; // Function pointer
      default:
        return "unknown";
    }
  }

  // ---------------------------------------------------------
  // 3. MAIN PARSE LOOP
  // Iterates through the signature string
  // ---------------------------------------------------------

  while (index < signature.length) {
    // 1. Identify the full range of the current type in the string
    const endIndex = findTypeEnd(signature, index);
    const typeRaw = signature.substring(index, endIndex);

    // 2. Decode it
    const decoded = decodeType(typeRaw);
    tokens.push(decoded);

    // 3. Advance
    index = endIndex;

    // 4. IMPORTANT: Skip Stack Offsets (Digits)
    // ObjC method signatures usually look like "v24@0:8i16"
    // We need to skip the numbers 24, 0, 8, 16 after parsing the types.
    while (index < signature.length && isDigit(signature[index])) {
      index++;
    }
  }

  // ---------------------------------------------------------
  // 4. FORMAT OUTPUT
  // ObjC Signature Layout: [Return Type, Self, _cmd, Arg1, Arg2...]
  // We want to hide Self (@) and _cmd (:) from the output args.
  // ---------------------------------------------------------

  if (tokens.length === 0) {
    return { args: [], ret: "void" };
  }

  const ret = tokens[0];

  // Standard methods have at least 3 parts: Ret, Self, Cmd.
  // If the signature is shorter (e.g. just a type string "i"), handle gracefully.
  let args = [];
  if (tokens.length > 3) {
    // Slice off Ret(0), Self(1), Cmd(2) -> Keep 3 onwards
    args = tokens.slice(3);
  } else {
    // If it doesn't look like a full method sig, just return what we found excluding ret
    args = tokens.slice(1);
  }

  return {
    args,
    ret,
  };
}
