const size = 1024;

let buf: NativePointer;
let initialized = false;
let demangler: (symbol: string) => string = (sym) => sym;

function load() {
  const canidates = [
    "/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib",
    "/usr/lib/swift/libswiftDemangle.dylib",
  ];

  for (const path of canidates) {
    try {
      return Module.load(path);
    } catch (e) {
      continue;
    }
  }
}

export function demangle(symbol: string) {
  if (initialized) {
    return demangler(symbol);
  }

  const mod = load();
  if (!mod) {
    console.warn("Unable to find swift demangler");
    return symbol;
  }

  const p = mod.findExportByName("swift_demangle_getDemangledName");
  if (!p) {
    console.warn("swift_demangle_getDemangledName not found");
    return symbol;
  }

  const getDemangledName = new NativeFunction(p, "uint", [
    "pointer",
    "pointer",
    "uint",
  ]);

  buf = Memory.alloc(size);
  demangler = (symbol: string) => {
    const len = getDemangledName(
      Memory.allocUtf8String(symbol),
      buf,
      size,
    ) as number;
    if (!len) {
      console.log("failed to demangle name", symbol);
      return symbol;
    }
    return buf.readUtf8String(len)!;
  };

  return demangler(symbol);
}
