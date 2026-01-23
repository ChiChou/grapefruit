const BUF_LEN = 256 * 1024;
const buf = Memory.alloc(BUF_LEN);

function cxaDemangle(name: string): string | null {
  const libcxxabi = Process.findModuleByName("libc++abi.dylib");
  if (!libcxxabi) return null;

  const demangle = new NativeFunction(
    libcxxabi.findExportByName("__cxa_demangle")!,
    "pointer",
    ["pointer", "pointer", "pointer", "pointer"],
  );

  const len = Memory.alloc(Process.pointerSize);
  const status = Memory.alloc(Process.pointerSize);

  len.writeUInt(BUF_LEN);
  const mangled = Memory.allocUtf8String(name);
  demangle(mangled, buf, len, status);

  const statusValue = status.readUInt();
  if (statusValue == 0) return buf.readUtf8String();
  console.error("__cxa_demangle failed, status: " + statusValue.toString(16));
  return null;
}

export interface ModuleInfo {
  name: string;
  size: number;
  version: string | null;
  path: string;
  base: string;
}

export function modules(): ModuleInfo[] {
  return Process.enumerateModules().map(
    ({ name, version, base, path, size }) => ({
      name,
      size,
      version,
      path,
      base: base.toString(),
    }),
  );
}

export function resolve(type: "objc" | "module", query: string) {
  const matches = new ApiResolver(type).enumerateMatches(query);
  return type === "module"
    ? matches.map((item) => {
        const [module, symbol] = item.name.split("!", 2);
        return Object.assign({}, item, { module, symbol });
      })
    : matches;
}

export function strings(path: string) {
  const mod = getModule(path);

  // do not include: __objc_methtype
  const valid = [
    "__objc_methname",
    "__cstring",
    "__dlopen_cstrs",
    "__objc_classname",
  ];
  const strings: string[] = [];
  const validSet = new Set(valid);

  for (const section of mod.enumerateSections()) {
    if (!validSet.has(section.name) || section.size <= 0) continue;

    const end = section.address.add(section.size);
    let p = section.address;
    while (p.compare(end) < 0) {
      const str = p.readUtf8String();
      if (!str) break;
      strings.push(str);
      p = p.add(str.length + 1);
    }
  }

  return strings;
}

function loadDemangler() {
  const canidates = [
    "/usr/lib/swift",
    "/System/Library/PrivateFrameworks/Swift/",
  ];
  for (const base of canidates) {
    try {
      return Module.load(`${base}/libswiftDemangle.dylib`);
    } catch (e) {
      continue;
    }
  }
}

let cachedSwiftDemangler: (name: string) => string | null;
function swiftDemangle(name: string) {
  if (cachedSwiftDemangler) return cachedSwiftDemangler(name);
  const mod = loadDemangler();
  if (mod) {
    const demangle = new NativeFunction(
      mod.findExportByName("swift_demangle_getDemangledName")!,
      "uint",
      ["pointer", "pointer", "uint"],
    );
    cachedSwiftDemangler = (name: string) => {
      const len = demangle(
        Memory.allocUtf8String(name),
        buf,
        BUF_LEN,
      ) as number;
      if (!len) return null;
      return buf.readUtf8String(len);
    };
    return cachedSwiftDemangler(name);
  }
  return null;
}

function tryDemangle(name: string): string | null {
  try {
    if (name.startsWith("_Z")) {
      return cxaDemangle(name);
    } else if (name.match(/(_T|_?\$[Ss])[_a-zA-Z0-9$.]+/)) {
      return swiftDemangle(name);
    }
  } catch (e) {}
  return null;
}

// accurate module lookup by path, to avoid name collision
function getModule(path: string) {
  const basename = path.substring(path.lastIndexOf("/") + 1);
  const match = Process.findModuleByName(basename);
  if (match && match.path === path) return match;

  // fallback to linear search
  const first = Process.enumerateModules().find((mod) => mod.path === path);
  if (first) return first;

  throw new Error(`Module not found: ${path}`);
}

type SymbolType = "f" | "v";

export interface Imported {
  name: string;
  addr: string;
  demangled: string | null;
  type: SymbolType | undefined;
}

export function imports(path: string, belongs: string): Imported[] {
  return getModule(path)
    .enumerateImports()
    .filter((imp) => imp.module === belongs)
    .map(({ name, address, type }) => {
      const demangled = tryDemangle(name);
      let t: SymbolType | undefined = undefined;
      if (type === "function") {
        t = "f";
      } else if (type === "variable") {
        t = "v";
      }

      return {
        name,
        addr: address?.toString() || "",
        demangled,
        type: t,
      };
    });
}

export function dependencies(path: string) {
  return getModule(path)
    .enumerateDependencies()
    .map((dep) => dep.name);
}

export interface Section {
  name: string;
  addr: string;
  size: number;
}

export function sections(path: string): Section[] {
  return getModule(path)
    .enumerateSections()
    .map((sec) => {
      const { name, address, size } = sec;
      return { name, addr: address.toString(), size };
    });
}

export interface Symbol {
  name: string;
  addr: string;
  demangled: string | null;
}

export function symbols(path: string): Symbol[] {
  return getModule(path)
    .enumerateSymbols()
    .filter((sym) => sym.name !== "<redacted>" && !sym.address.isNull())
    .map((sym) => {
      const { name, address } = sym;
      const demangled = tryDemangle(name);

      return {
        name,
        addr: address.toString(),
        demangled,
      };
    });
}

export interface Exported {
  name: string;
  addr: string;
  demangled: string | null;
  type: SymbolType;
}

export function exports(path: string): Exported[] {
  return getModule(path)
    .enumerateExports()
    .filter((exp) => !exp.address.isNull())
    .map(({ name, address, type }) => {
      const demangled = tryDemangle(name);
      return {
        name,
        addr: address.toString(),
        demangled,
        type: type === "function" ? "f" : "v",
      };
    });
}
