import ObjC from "frida-objc-bridge";
import { getGlobalExport } from "@/lib/polyfill.js";
import getLibSystemApi from "@/fruity/native/libsystem.js";

// struct nlist_64 {
//     union {
//         uint32_t n_strx;  /* index into the string table */
//     } n_un;
//     uint8_t n_type;       /* section number or NO_SECT */
//     uint8_t n_sect;       /* see <mach-o/stab.h> */
//     uint16_t n_desc;      /* see <mach-o/stab.h> */
//     uint64_t n_value;     /* value of this symbol (or stab offset) */
// };

let cached: {
  dyldForEachInstalledSharedCache: NativeFunction<void, [NativePointerValue]>;
  dyldSharedCacheForEachImage: NativeFunction<
    void,
    [NativePointerValue, NativePointerValue]
  >;
  dyldImageGetInstallname: NativeFunction<NativePointer, [NativePointerValue]>;
  dyldImageLocalNlistContent4Symbolication: NativeFunction<
    number,
    [NativePointerValue, NativePointerValue]
  >;
  _dyld_image_count: NativeFunction<number, []>;
  _dyld_get_image_header: NativeFunction<NativePointer, [number]>;
  _dyld_get_image_vmaddr_slide: NativeFunction<Int64, [number]>;
};

function api() {
  if (cached) return cached;

  const libdyld = Module.load("/usr/lib/system/libdyld.dylib");

  function requireExport(name: string) {
    const addr = libdyld.findExportByName(name);
    if (!addr) throw new Error(`${name} not found`);
    return addr;
  }

  cached = {
    dyldForEachInstalledSharedCache: new NativeFunction(
      requireExport("dyld_for_each_installed_shared_cache"),
      "void",
      ["pointer"],
    ),
    dyldSharedCacheForEachImage: new NativeFunction(
      requireExport("dyld_shared_cache_for_each_image"),
      "void",
      ["pointer", "pointer"],
    ),
    dyldImageGetInstallname: new NativeFunction(
      requireExport("dyld_image_get_installname"),
      "pointer",
      ["pointer"],
    ),
    dyldImageLocalNlistContent4Symbolication: new NativeFunction(
      requireExport("dyld_image_local_nlist_content_4Symbolication"),
      "bool",
      ["pointer", "pointer"],
    ),
    _dyld_image_count: new NativeFunction(
      getGlobalExport("_dyld_image_count"),
      "uint32",
      [],
    ),
    _dyld_get_image_header: new NativeFunction(
      getGlobalExport("_dyld_get_image_header"),
      "pointer",
      ["uint32"],
    ),
    _dyld_get_image_vmaddr_slide: new NativeFunction(
      getGlobalExport("_dyld_get_image_vmaddr_slide"),
      "int64",
      ["uint32"],
    ),
  };

  return cached;
}

function getSlide(module: string) {
  const {
    _dyld_image_count,
    _dyld_get_image_header,
    _dyld_get_image_vmaddr_slide,
  } = api();

  const moduleInfo = Process.getModuleByName(module);
  for (let i = 0; i < _dyld_image_count(); i++) {
    const header = _dyld_get_image_header(i);
    if (moduleInfo.base.equals(header)) {
      return _dyld_get_image_vmaddr_slide(i);
    }
  }

  throw new Error(`module ${module} not found in current process`);
}

/**
 * Iterate over nlist symbols in the dyld shared cache for a given module.
 * @param visitor called for each symbol; return true to stop iteration.
 */
function forEachSymbolInDyld(
  module: string,
  visitor: (symbolName: NativePointer, value: UInt64) => boolean,
) {
  const {
    dyldForEachInstalledSharedCache,
    dyldSharedCacheForEachImage,
    dyldImageGetInstallname,
    dyldImageLocalNlistContent4Symbolication,
  } = api();

  dyldForEachInstalledSharedCache(
    new ObjC.Block({
      retType: "void",
      argTypes: ["pointer"],
      implementation(cache: NativePointer) {
        let found = false;

        dyldSharedCacheForEachImage(
          cache,
          new ObjC.Block({
            retType: "void",
            argTypes: ["pointer"],
            implementation(image: NativePointer) {
              if (found) return;

              const name = dyldImageGetInstallname(image).readUtf8String()!;
              if (!name.endsWith("/" + module)) return;
              found = true;

              dyldImageLocalNlistContent4Symbolication(
                image,
                new ObjC.Block({
                  retType: "bool",
                  argTypes: ["pointer", "uint64", "pointer"],
                  implementation(
                    nlistStart: NativePointer,
                    nlistCount: UInt64,
                    stringTable: NativePointer,
                  ) {
                    let nlist = nlistStart;
                    for (
                      let i = uint64(0);
                      i.compare(nlistCount) < 0;
                      i = i.add(1), nlist = nlist.add(16)
                    ) {
                      const n_strx = nlist.readU32();
                      const n_value = nlist.add(8).readU64();
                      const symbolName = stringTable.add(n_strx);
                      if (visitor(symbolName, n_value)) {
                        break;
                      }
                    }
                  },
                }),
              );
            },
          }),
        );
      },
    }),
  );
}

function findSymbolInDyld(module: string, symbol: string) {
  const { strcmp } = getLibSystemApi();
  let value = NULL;
  const symbolString = Memory.allocUtf8String("_" + symbol);

  forEachSymbolInDyld(module, (symbolName, n_value) => {
    if (strcmp(symbolName, symbolString) === 0) {
      value = new NativePointer(n_value);
      return true;
    }
    return false;
  });

  if (value.isNull())
    throw new Error(
      `symbol ${symbol} not found in dyld cache for module ${module}`,
    );

  const slide = getSlide(module);
  return value.add(slide);
}

function globSymbolsInDyld(module: string, pattern: string) {
  const { fnmatch } = getLibSystemApi();
  const results: NativePointer[] = [];
  const patternString = Memory.allocUtf8String("_" + pattern);

  forEachSymbolInDyld(module, (symbolName, n_value) => {
    if (fnmatch(patternString, symbolName, 0) === 0) {
      results.push(new NativePointer(n_value));
    }
    return false;
  });

  const slide = getSlide(module);
  return results.map((ptr) => ptr.add(slide));
}

export function symbolFromName(module: string, symbol: string): NativePointer {
  try {
    return findSymbolInDyld(module, symbol);
  } catch (e) {
    console.warn("libdyld: error finding symbol in dyld cache:", e);
    return DebugSymbol.getFunctionByName(symbol);
  }
}

export function symbolsFromGlob(
  module: string,
  pattern: string,
): NativePointer[] {
  try {
    return globSymbolsInDyld(module, pattern);
  } catch (e) {
    console.warn("libdyld: could not match glob pattern in dyld cache:", e);
    return DebugSymbol.findFunctionsMatching(pattern);
  }
}
