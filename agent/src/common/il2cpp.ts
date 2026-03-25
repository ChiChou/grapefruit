// IL2CPP support powered by frida-il2cpp-bridge
// Copyright (c) 2021-2026 vfsfitvnm — MIT License
// https://github.com/vfsfitvnm/frida-il2cpp-bridge

import "frida-il2cpp-bridge";

// ── Serializable types ──────────────────────────────────────────────

export interface Il2CppAssemblyInfo {
  name: string;
  classCount: number;
}

export interface Il2CppClassInfo {
  name: string;
  fullName: string;
  namespace: string | undefined;
  assemblyName: string;
  isAbstract: boolean;
  isEnum: boolean;
  isInterface: boolean;
  isStruct: boolean;
  isValueType: boolean;
  isGeneric: boolean;
  instanceSize: number;
}

export interface Il2CppFieldInfo {
  name: string;
  typeName: string;
  offset: number;
  isStatic: boolean;
  isLiteral: boolean;
  modifier: string | undefined;
}

export interface Il2CppMethodInfo {
  name: string;
  returnType: string;
  parameters: { name: string; typeName: string }[];
  rva: string;
  isStatic: boolean;
  isGeneric: boolean;
  modifier: string | undefined;
}

export interface Il2CppClassDetail {
  info: Il2CppClassInfo;
  parent: string | null;
  interfaces: string[];
  nestedClasses: string[];
  fields: Il2CppFieldInfo[];
  methods: Il2CppMethodInfo[];
}

export interface Il2CppGCStats {
  heapSize: string;
  usedHeapSize: string;
  isEnabled: boolean;
  isIncremental: boolean;
}

export interface Il2CppThreadInfo {
  id: number;
  managedId: number;
  isFinalizer: boolean;
}

export interface Il2CppRuntimeInfo {
  unityVersion: string;
  moduleName: string;
  moduleBase: string;
  moduleSize: number;
  appIdentifier: string;
  appVersion: string;
  appDataPath: string | null;
  assemblyCount: number;
  gc: Il2CppGCStats;
}

// ── Init guard ──────────────────────────────────────────────────────

let ready = false;

function withIl2Cpp<T>(block: () => T): T | Promise<T> {
  if (ready) return block();
  return Il2Cpp.perform(() => {
    ready = true;
    return block();
  });
}

// ── Helpers ─────────────────────────────────────────────────────────

function findImage(assemblyName: string): Il2Cpp.Image {
  const asm = Il2Cpp.domain.tryAssembly(assemblyName);
  if (!asm) throw new Error(`assembly ${assemblyName} not found`);
  return asm.image;
}

function findClass(assemblyName: string, fullName: string): Il2Cpp.Class {
  const image = findImage(assemblyName);
  const klass = image.tryClass(fullName);
  if (!klass) throw new Error(`class ${fullName} not found in ${assemblyName}`);
  return klass;
}

function serializeClassInfo(klass: Il2Cpp.Class): Il2CppClassInfo {
  return {
    name: klass.name,
    fullName: klass.fullName,
    namespace: klass.namespace,
    assemblyName: klass.assemblyName,
    isAbstract: klass.isAbstract,
    isEnum: klass.isEnum,
    isInterface: klass.isInterface,
    isStruct: klass.isStruct,
    isValueType: klass.isValueType,
    isGeneric: klass.isGeneric,
    instanceSize: klass.instanceSize,
  };
}

function serializeField(f: Il2Cpp.Field): Il2CppFieldInfo {
  return {
    name: f.name,
    typeName: f.type.name,
    offset: f.offset,
    isStatic: f.isStatic,
    isLiteral: f.isLiteral,
    modifier: f.modifier,
  };
}

function serializeMethod(m: Il2Cpp.Method): Il2CppMethodInfo {
  return {
    name: m.name,
    returnType: m.returnType.name,
    parameters: m.parameters.map((p) => ({
      name: p.name,
      typeName: p.type.name,
    })),
    rva: m.virtualAddress.isNull()
      ? ""
      : `0x${m.relativeVirtualAddress.toString(16).padStart(8, "0")}`,
    isStatic: m.isStatic,
    isGeneric: m.isGeneric,
    modifier: m.modifier,
  };
}

// ── RPC exports ─────────────────────────────────────────────────────

/** Check if IL2CPP is available in the current process */
export function available(): boolean {
  const names = [
    "libil2cpp.so",
    "GameAssembly.so",
    "GameAssembly.dll",
    "UnityFramework",
    "GameAssembly.dylib",
  ];
  return names.some((n) => Process.findModuleByName(n) !== null);
}

/** Get IL2CPP runtime info */
export function info() {
  return withIl2Cpp((): Il2CppRuntimeInfo => {
    return {
      unityVersion: Il2Cpp.unityVersion,
      moduleName: Il2Cpp.module.name,
      moduleBase: Il2Cpp.module.base.toString(),
      moduleSize: Il2Cpp.module.size,
      appIdentifier: Il2Cpp.application.identifier,
      appVersion: Il2Cpp.application.version,
      appDataPath: Il2Cpp.application.dataPath,
      assemblyCount: Il2Cpp.domain.assemblies.length,
      gc: {
        heapSize: Il2Cpp.gc.heapSize.toString(),
        usedHeapSize: Il2Cpp.gc.usedHeapSize.toString(),
        isEnabled: Il2Cpp.gc.isEnabled,
        isIncremental: Il2Cpp.gc.isIncremental,
      },
    };
  });
}

/** List all assemblies */
export function assemblies() {
  return withIl2Cpp((): Il2CppAssemblyInfo[] => {
    return Il2Cpp.domain.assemblies.map((asm) => ({
      name: asm.name,
      classCount: asm.image.classCount,
    }));
  });
}

/** List classes in an assembly */
export function classes(assemblyName: string) {
  return withIl2Cpp((): string[] => {
    const image = findImage(assemblyName);
    return image.classes.map((c) => c.fullName);
  });
}

/** Search classes across all assemblies */
export function searchClasses(query: string) {
  return withIl2Cpp((): { assemblyName: string; fullName: string }[] => {
    const q = query.toLowerCase();
    const results: { assemblyName: string; fullName: string }[] = [];

    for (const asm of Il2Cpp.domain.assemblies) {
      for (const klass of asm.image.classes) {
        if (klass.fullName.toLowerCase().includes(q)) {
          results.push({
            assemblyName: asm.name,
            fullName: klass.fullName,
          });
        }
        if (results.length >= 500) return results;
      }
    }
    return results;
  });
}

/** Get class detail */
export function classDetail(assemblyName: string, fullName: string) {
  return withIl2Cpp((): Il2CppClassDetail => {
    const klass = findClass(assemblyName, fullName);
    return {
      info: serializeClassInfo(klass),
      parent: klass.parent?.fullName ?? null,
      interfaces: klass.interfaces.map((i) => i.fullName),
      nestedClasses: klass.nestedClasses.map((c) => c.fullName),
      fields: klass.fields.map(serializeField),
      methods: klass.methods.map(serializeMethod),
    };
  });
}

/** Dump class as C# source */
export function classDump(assemblyName: string, fullName: string) {
  return withIl2Cpp((): string => {
    const klass = findClass(assemblyName, fullName);
    return klass.toString();
  });
}

/** Get GC stats */
export function gcStats() {
  return withIl2Cpp(
    (): Il2CppGCStats => ({
      heapSize: Il2Cpp.gc.heapSize.toString(),
      usedHeapSize: Il2Cpp.gc.usedHeapSize.toString(),
      isEnabled: Il2Cpp.gc.isEnabled,
      isIncremental: Il2Cpp.gc.isIncremental,
    }),
  );
}

/** Force GC collection */
export function gcCollect(generation: number) {
  return withIl2Cpp(() => {
    const gen = Math.max(0, Math.min(2, generation)) as 0 | 1 | 2;
    Il2Cpp.gc.collect(gen);
  });
}

/** Enable/disable GC */
export function gcToggle(enabled: boolean) {
  return withIl2Cpp(() => {
    Il2Cpp.gc.isEnabled = enabled;
  });
}

/** List managed threads */
export function threads() {
  return withIl2Cpp((): Il2CppThreadInfo[] => {
    return Il2Cpp.attachedThreads.map((t) => ({
      id: t.id,
      managedId: t.managedId,
      isFinalizer: t.isFinalizer,
    }));
  });
}
