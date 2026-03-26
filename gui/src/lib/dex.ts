/**
 * Pure TypeScript DEX file parser.
 *
 * Parses Dalvik Executable (DEX) files entirely in the browser.
 * Reference: https://source.android.com/docs/core/runtime/dex-format
 */

export interface DexHeader {
  magic: string;
  checksum: number;
  fileSize: number;
  headerSize: number;
  endianTag: number;
  stringIdsSize: number;
  typeIdsSize: number;
  protoIdsSize: number;
  fieldIdsSize: number;
  methodIdsSize: number;
  classDefsSize: number;
}

export interface DexString {
  index: number;
  value: string;
}

export interface DexType {
  index: number;
  descriptorIdx: number;
  descriptor: string;
  name: string;
}

export interface DexProto {
  shortyIdx: number;
  returnTypeIdx: number;
  parametersOff: number;
  shorty: string;
  returnType: string;
  parameterTypes: string[];
}

export interface DexField {
  classIdx: number;
  typeIdx: number;
  nameIdx: number;
  className: string;
  typeName: string;
  name: string;
}

export interface DexMethodDef {
  classIdx: number;
  protoIdx: number;
  nameIdx: number;
  className: string;
  protoShorty: string;
  name: string;
  returnType: string;
  parameterTypes: string[];
}

export interface DexClassField {
  fieldIdx: number;
  accessFlags: number;
  name: string;
  type: string;
  accessString: string;
}

export interface DexClassMethod {
  methodIdx: number;
  accessFlags: number;
  codeOff: number;
  name: string;
  returnType: string;
  parameterTypes: string[];
  accessString: string;
  registersSize: number;
  insSize: number;
  outsSize: number;
  codeSize: number;
}

export interface DexClassDef {
  classIdx: number;
  accessFlags: number;
  superclassIdx: number;
  interfacesOff: number;
  sourceFileIdx: number;
  className: string;
  superclassName: string;
  accessString: string;
  sourceFile: string;
  interfaces: string[];
  staticFields: DexClassField[];
  instanceFields: DexClassField[];
  directMethods: DexClassMethod[];
  virtualMethods: DexClassMethod[];
}

export interface StringXref {
  className: string;
  methodName: string;
  methodIdx: number;
  codeOffset: number;
}

export interface DexFile {
  header: DexHeader;
  strings: DexString[];
  types: DexType[];
  protos: DexProto[];
  fields: DexField[];
  methods: DexMethodDef[];
  classes: DexClassDef[];
  data: DataView;
}

const ACC_PUBLIC = 0x1;
const ACC_PRIVATE = 0x2;
const ACC_PROTECTED = 0x4;
const ACC_STATIC = 0x8;
const ACC_FINAL = 0x10;
const ACC_SYNCHRONIZED = 0x20;
const ACC_VOLATILE = 0x40;
const ACC_BRIDGE = 0x40;
const ACC_TRANSIENT = 0x80;
const ACC_VARARGS = 0x80;
const ACC_NATIVE = 0x100;
const ACC_INTERFACE = 0x200;
const ACC_ABSTRACT = 0x400;
const ACC_STRICT = 0x800;
const ACC_SYNTHETIC = 0x1000;
const ACC_ANNOTATION = 0x2000;
const ACC_ENUM = 0x4000;
const ACC_CONSTRUCTOR = 0x10000;
const ACC_DECLARED_SYNCHRONIZED = 0x20000;

function accessFlagsToString(flags: number, isMethod: boolean): string {
  const parts: string[] = [];
  if (flags & ACC_PUBLIC) parts.push("public");
  if (flags & ACC_PRIVATE) parts.push("private");
  if (flags & ACC_PROTECTED) parts.push("protected");
  if (flags & ACC_STATIC) parts.push("static");
  if (flags & ACC_FINAL) parts.push("final");
  if (isMethod) {
    if (flags & ACC_SYNCHRONIZED) parts.push("synchronized");
    if (flags & ACC_BRIDGE) parts.push("bridge");
    if (flags & ACC_VARARGS) parts.push("varargs");
    if (flags & ACC_NATIVE) parts.push("native");
  } else {
    if (flags & ACC_VOLATILE) parts.push("volatile");
    if (flags & ACC_TRANSIENT) parts.push("transient");
  }
  if (flags & ACC_ABSTRACT) parts.push("abstract");
  if (flags & ACC_STRICT) parts.push("strictfp");
  if (flags & ACC_SYNTHETIC) parts.push("synthetic");
  if (flags & ACC_ENUM) parts.push("enum");
  if (flags & ACC_INTERFACE) parts.push("interface");
  if (flags & ACC_ANNOTATION) parts.push("annotation");
  if (flags & ACC_CONSTRUCTOR) parts.push("constructor");
  if (flags & ACC_DECLARED_SYNCHRONIZED) parts.push("declared-synchronized");
  return parts.join(" ");
}

function classAccessToString(flags: number): string {
  const parts: string[] = [];
  if (flags & ACC_PUBLIC) parts.push("public");
  if (flags & ACC_PRIVATE) parts.push("private");
  if (flags & ACC_PROTECTED) parts.push("protected");
  if (flags & ACC_STATIC) parts.push("static");
  if (flags & ACC_FINAL) parts.push("final");
  if (flags & ACC_INTERFACE) parts.push("interface");
  if (flags & ACC_ABSTRACT) parts.push("abstract");
  if (flags & ACC_SYNTHETIC) parts.push("synthetic");
  if (flags & ACC_ANNOTATION) parts.push("annotation");
  if (flags & ACC_ENUM) parts.push("enum");
  return parts.join(" ");
}

export function descriptorToName(desc: string): string {
  if (!desc) return "";
  switch (desc) {
    case "V":
      return "void";
    case "Z":
      return "boolean";
    case "B":
      return "byte";
    case "S":
      return "short";
    case "C":
      return "char";
    case "I":
      return "int";
    case "J":
      return "long";
    case "F":
      return "float";
    case "D":
      return "double";
  }
  if (desc.startsWith("[")) return descriptorToName(desc.slice(1)) + "[]";
  if (desc.startsWith("L") && desc.endsWith(";"))
    return desc.slice(1, -1).replace(/\//g, ".");
  return desc;
}

interface Cursor {
  offset: number;
}

function readULeb128(dv: DataView, cur: Cursor): number {
  let result = 0;
  let shift = 0;
  let byte: number;
  do {
    byte = dv.getUint8(cur.offset++);
    result |= (byte & 0x7f) << shift;
    shift += 7;
  } while (byte & 0x80);
  return result;
}

function readMutf8(dv: DataView, offset: number): string {
  const cur: Cursor = { offset };
  readULeb128(dv, cur); // char count — not needed

  let result = "";
  for (;;) {
    const a = dv.getUint8(cur.offset++);
    if (a === 0) break;
    if ((a & 0x80) === 0) {
      result += String.fromCharCode(a);
    } else if ((a & 0xe0) === 0xc0) {
      const b = dv.getUint8(cur.offset++);
      result += String.fromCharCode(((a & 0x1f) << 6) | (b & 0x3f));
    } else if ((a & 0xf0) === 0xe0) {
      const b = dv.getUint8(cur.offset++);
      const c = dv.getUint8(cur.offset++);
      result += String.fromCharCode(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
    } else {
      result += "\uFFFD";
    }
  }
  return result;
}

export function parseDex(buffer: ArrayBuffer): DexFile {
  const dv = new DataView(buffer);

  const rawMagic = new Uint8Array(buffer, 0, 8);
  let magicEnd = rawMagic.indexOf(0);
  if (magicEnd === -1) magicEnd = 8;
  const magic = new TextDecoder().decode(rawMagic.subarray(0, magicEnd));

  if (!magic.startsWith("dex\n")) {
    throw new Error("Not a valid DEX file");
  }

  const header: DexHeader = {
    magic,
    checksum: dv.getUint32(8, true),
    fileSize: dv.getUint32(32, true),
    headerSize: dv.getUint32(36, true),
    endianTag: dv.getUint32(40, true),
    stringIdsSize: dv.getUint32(56, true),
    typeIdsSize: dv.getUint32(64, true),
    protoIdsSize: dv.getUint32(72, true),
    fieldIdsSize: dv.getUint32(80, true),
    methodIdsSize: dv.getUint32(88, true),
    classDefsSize: dv.getUint32(96, true),
  };

  const stringIdsOff = dv.getUint32(60, true);
  const typeIdsOff = dv.getUint32(68, true);
  const protoIdsOff = dv.getUint32(76, true);
  const fieldIdsOff = dv.getUint32(84, true);
  const methodIdsOff = dv.getUint32(92, true);
  const classDefsOff = dv.getUint32(100, true);

  const strings: DexString[] = [];
  for (let i = 0; i < header.stringIdsSize; i++) {
    const dataOff = dv.getUint32(stringIdsOff + i * 4, true);
    strings.push({ index: i, value: readMutf8(dv, dataOff) });
  }

  const str = (idx: number) =>
    idx >= 0 && idx < strings.length ? strings[idx].value : "";

  const types: DexType[] = [];
  for (let i = 0; i < header.typeIdsSize; i++) {
    const descriptorIdx = dv.getUint32(typeIdsOff + i * 4, true);
    const descriptor = str(descriptorIdx);
    types.push({
      index: i,
      descriptorIdx,
      descriptor,
      name: descriptorToName(descriptor),
    });
  }

  const typeName = (idx: number) =>
    idx >= 0 && idx < types.length ? types[idx].name : "";

  const protos: DexProto[] = [];
  for (let i = 0; i < header.protoIdsSize; i++) {
    const off = protoIdsOff + i * 12;
    const shortyIdx = dv.getUint32(off, true);
    const returnTypeIdx = dv.getUint32(off + 4, true);
    const parametersOff = dv.getUint32(off + 8, true);
    const parameterTypes: string[] = [];
    if (parametersOff !== 0) {
      const paramCount = dv.getUint32(parametersOff, true);
      for (let j = 0; j < paramCount; j++) {
        const typeIdx = dv.getUint16(parametersOff + 4 + j * 2, true);
        parameterTypes.push(typeName(typeIdx));
      }
    }
    protos.push({
      shortyIdx,
      returnTypeIdx,
      parametersOff,
      shorty: str(shortyIdx),
      returnType: typeName(returnTypeIdx),
      parameterTypes,
    });
  }

  const fields: DexField[] = [];
  for (let i = 0; i < header.fieldIdsSize; i++) {
    const off = fieldIdsOff + i * 8;
    const classIdx = dv.getUint16(off, true);
    const typeIdx = dv.getUint16(off + 2, true);
    const nameIdx = dv.getUint32(off + 4, true);
    fields.push({
      classIdx,
      typeIdx,
      nameIdx,
      className: typeName(classIdx),
      typeName: typeName(typeIdx),
      name: str(nameIdx),
    });
  }

  const methods: DexMethodDef[] = [];
  for (let i = 0; i < header.methodIdsSize; i++) {
    const off = methodIdsOff + i * 8;
    const classIdx = dv.getUint16(off, true);
    const protoIdx = dv.getUint16(off + 2, true);
    const nameIdx = dv.getUint32(off + 4, true);
    const proto = protos[protoIdx];
    methods.push({
      classIdx,
      protoIdx,
      nameIdx,
      className: typeName(classIdx),
      protoShorty: proto?.shorty ?? "",
      name: str(nameIdx),
      returnType: proto?.returnType ?? "",
      parameterTypes: proto?.parameterTypes ?? [],
    });
  }

  const classes: DexClassDef[] = [];
  for (let i = 0; i < header.classDefsSize; i++) {
    const off = classDefsOff + i * 32;
    const classIdx = dv.getUint32(off, true);
    const accessFlags = dv.getUint32(off + 4, true);
    const superclassIdx = dv.getUint32(off + 8, true);
    const interfacesOff = dv.getUint32(off + 12, true);
    const sourceFileIdx = dv.getUint32(off + 16, true);
    const classDataOff = dv.getUint32(off + 24, true);

    const ifaces: string[] = [];
    if (interfacesOff !== 0) {
      const ifaceCount = dv.getUint32(interfacesOff, true);
      for (let j = 0; j < ifaceCount; j++) {
        const tIdx = dv.getUint16(interfacesOff + 4 + j * 2, true);
        ifaces.push(typeName(tIdx));
      }
    }

    const staticFields: DexClassField[] = [];
    const instanceFields: DexClassField[] = [];
    const directMethods: DexClassMethod[] = [];
    const virtualMethods: DexClassMethod[] = [];

    if (classDataOff !== 0) {
      const cur: Cursor = { offset: classDataOff };
      const staticFieldsSize = readULeb128(dv, cur);
      const instanceFieldsSize = readULeb128(dv, cur);
      const directMethodsSize = readULeb128(dv, cur);
      const virtualMethodsSize = readULeb128(dv, cur);

      let fieldIdx = 0;
      for (let j = 0; j < staticFieldsSize; j++) {
        fieldIdx += readULeb128(dv, cur);
        const af = readULeb128(dv, cur);
        const f = fields[fieldIdx];
        staticFields.push({
          fieldIdx,
          accessFlags: af,
          name: f?.name ?? `field_${fieldIdx}`,
          type: f?.typeName ?? "?",
          accessString: accessFlagsToString(af, false),
        });
      }

      fieldIdx = 0;
      for (let j = 0; j < instanceFieldsSize; j++) {
        fieldIdx += readULeb128(dv, cur);
        const af = readULeb128(dv, cur);
        const f = fields[fieldIdx];
        instanceFields.push({
          fieldIdx,
          accessFlags: af,
          name: f?.name ?? `field_${fieldIdx}`,
          type: f?.typeName ?? "?",
          accessString: accessFlagsToString(af, false),
        });
      }

      const readMethods = (count: number, out: DexClassMethod[]) => {
        let mIdx = 0;
        for (let j = 0; j < count; j++) {
          mIdx += readULeb128(dv, cur);
          const af = readULeb128(dv, cur);
          const codeOff = readULeb128(dv, cur);
          const m = methods[mIdx];
          let registersSize = 0,
            insSize = 0,
            outsSize = 0,
            codeSize = 0;
          if (codeOff !== 0) {
            registersSize = dv.getUint16(codeOff, true);
            insSize = dv.getUint16(codeOff + 2, true);
            outsSize = dv.getUint16(codeOff + 4, true);
            codeSize = dv.getUint32(codeOff + 12, true);
          }
          out.push({
            methodIdx: mIdx,
            accessFlags: af,
            codeOff,
            name: m?.name ?? `method_${mIdx}`,
            returnType: m?.returnType ?? "?",
            parameterTypes: m?.parameterTypes ?? [],
            accessString: accessFlagsToString(af, true),
            registersSize,
            insSize,
            outsSize,
            codeSize,
          });
        }
      };

      readMethods(directMethodsSize, directMethods);
      readMethods(virtualMethodsSize, virtualMethods);
    }

    classes.push({
      classIdx,
      accessFlags,
      superclassIdx,
      interfacesOff,
      sourceFileIdx: sourceFileIdx === 0xffffffff ? -1 : sourceFileIdx,
      className: typeName(classIdx),
      superclassName:
        superclassIdx !== 0xffffffff ? typeName(superclassIdx) : "",
      accessString: classAccessToString(accessFlags),
      sourceFile: sourceFileIdx !== 0xffffffff ? str(sourceFileIdx) : "",
      interfaces: ifaces,
      staticFields,
      instanceFields,
      directMethods,
      virtualMethods,
    });
  }

  return { header, strings, types, protos, fields, methods, classes, data: dv };
}

export function disassembleMethod(
  dex: DexFile,
  method: DexClassMethod,
): string[] {
  if (method.codeOff === 0) return ["; (no code — native or abstract)"];

  const dv = dex.data;
  const insnsOff = method.codeOff + 16;
  const insnsSize = method.codeSize;
  const lines: string[] = [];
  let pc = 0;

  const str = (idx: number) =>
    idx >= 0 && idx < dex.strings.length
      ? dex.strings[idx].value
      : `string@${idx}`;
  const typ = (idx: number) =>
    idx >= 0 && idx < dex.types.length ? dex.types[idx].name : `type@${idx}`;
  const fld = (idx: number) => {
    if (idx >= 0 && idx < dex.fields.length) {
      const f = dex.fields[idx];
      return `${f.className}.${f.name}:${f.typeName}`;
    }
    return `field@${idx}`;
  };
  const mth = (idx: number) => {
    if (idx >= 0 && idx < dex.methods.length) {
      const m = dex.methods[idx];
      return `${m.className}.${m.name}`;
    }
    return `method@${idx}`;
  };

  function u16(): number {
    if (pc >= insnsSize) return 0;
    const v = dv.getUint16(insnsOff + pc * 2, true);
    pc++;
    return v;
  }
  function s16(): number {
    const v = u16();
    return v > 0x7fff ? v - 0x10000 : v;
  }
  function u32(): number {
    const lo = u16();
    const hi = u16();
    return (hi << 16) | lo;
  }
  function s32(): number {
    const v = u32();
    return v > 0x7fffffff ? v - 0x100000000 : v;
  }
  function hex(n: number): string {
    return "0x" + (n >>> 0).toString(16);
  }
  function reg(n: number): string {
    return `v${n}`;
  }

  while (pc < insnsSize) {
    const startPc = pc;
    const word = u16();
    const op = word & 0xff;
    const vA4 = (word >> 8) & 0xf;
    const vB4 = (word >> 12) & 0xf;
    const vAA = (word >> 8) & 0xff;
    let line = "";

    switch (op) {
      case 0x00:
        line = "nop";
        break;
      case 0x01:
        line = `move ${reg(vA4)}, ${reg(vB4)}`;
        break;
      case 0x02: {
        const b = u16();
        line = `move/from16 ${reg(vAA)}, ${reg(b)}`;
        break;
      }
      case 0x04:
        line = `move-wide ${reg(vA4)}, ${reg(vB4)}`;
        break;
      case 0x05: {
        const b = u16();
        line = `move-wide/from16 ${reg(vAA)}, ${reg(b)}`;
        break;
      }
      case 0x07:
        line = `move-object ${reg(vA4)}, ${reg(vB4)}`;
        break;
      case 0x08: {
        const b = u16();
        line = `move-object/from16 ${reg(vAA)}, ${reg(b)}`;
        break;
      }
      case 0x0a:
        line = `move-result ${reg(vAA)}`;
        break;
      case 0x0b:
        line = `move-result-wide ${reg(vAA)}`;
        break;
      case 0x0c:
        line = `move-result-object ${reg(vAA)}`;
        break;
      case 0x0d:
        line = `move-exception ${reg(vAA)}`;
        break;
      case 0x0e:
        line = "return-void";
        break;
      case 0x0f:
        line = `return ${reg(vAA)}`;
        break;
      case 0x10:
        line = `return-wide ${reg(vAA)}`;
        break;
      case 0x11:
        line = `return-object ${reg(vAA)}`;
        break;
      case 0x12:
        line = `const/4 ${reg(vA4)}, ${vB4 > 7 ? vB4 - 16 : vB4}`;
        break;
      case 0x13: {
        const b = s16();
        line = `const/16 ${reg(vAA)}, ${b}`;
        break;
      }
      case 0x14: {
        const b = s32();
        line = `const ${reg(vAA)}, ${hex(b)}`;
        break;
      }
      case 0x15: {
        const b = s16();
        line = `const/high16 ${reg(vAA)}, ${hex(b << 16)}`;
        break;
      }
      case 0x16: {
        const b = s16();
        line = `const-wide/16 ${reg(vAA)}, ${b}`;
        break;
      }
      case 0x17: {
        const b = s32();
        line = `const-wide/32 ${reg(vAA)}, ${b}`;
        break;
      }
      case 0x18: {
        const lo = u32();
        const hi = u32();
        line = `const-wide ${reg(vAA)}, ${hex(hi)}${hex(lo).slice(2)}`;
        break;
      }
      case 0x19: {
        const b = s16();
        line = `const-wide/high16 ${reg(vAA)}, ${hex(b)}`;
        break;
      }
      case 0x1a: {
        const b = u16();
        line = `const-string ${reg(vAA)}, "${str(b)}"`;
        break;
      }
      case 0x1b: {
        const b = u32();
        line = `const-string/jumbo ${reg(vAA)}, "${str(b)}"`;
        break;
      }
      case 0x1c: {
        const b = u16();
        line = `const-class ${reg(vAA)}, ${typ(b)}`;
        break;
      }
      case 0x1d:
        line = `monitor-enter ${reg(vAA)}`;
        break;
      case 0x1e:
        line = `monitor-exit ${reg(vAA)}`;
        break;
      case 0x1f: {
        const b = u16();
        line = `check-cast ${reg(vAA)}, ${typ(b)}`;
        break;
      }
      case 0x20: {
        const b = u16();
        line = `instance-of ${reg(vA4)}, ${reg(vB4)}, ${typ(b)}`;
        break;
      }
      case 0x21:
        line = `array-length ${reg(vA4)}, ${reg(vB4)}`;
        break;
      case 0x22: {
        const b = u16();
        line = `new-instance ${reg(vAA)}, ${typ(b)}`;
        break;
      }
      case 0x23: {
        const b = u16();
        line = `new-array ${reg(vA4)}, ${reg(vB4)}, ${typ(b)}`;
        break;
      }
      case 0x24: {
        const b = u16();
        const c = u16();
        const count = vA4;
        const regs = [];
        for (let i = 0; i < count && i < 5; i++)
          regs.push(reg((c >> (i * 4)) & 0xf));
        line = `filled-new-array {${regs.join(", ")}}, ${typ(b)}`;
        break;
      }
      case 0x27:
        line = `throw ${reg(vAA)}`;
        break;
      case 0x28: {
        const off = vAA > 127 ? vAA - 256 : vAA;
        line = `goto ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x29: {
        const off = s16();
        line = `goto/16 ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x2a: {
        const off = s32();
        line = `goto/32 ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x2b: {
        const off = s32();
        line = `packed-switch ${reg(vAA)}, ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x2c: {
        const off = s32();
        line = `sparse-switch ${reg(vAA)}, ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x2d:
      case 0x2e:
      case 0x2f:
      case 0x30:
      case 0x31: {
        const names = [
          "cmpl-float",
          "cmpg-float",
          "cmpl-double",
          "cmpg-double",
          "cmp-long",
        ];
        const b = u16();
        line = `${names[op - 0x2d]} ${reg(vAA)}, ${reg(b & 0xff)}, ${reg((b >> 8) & 0xff)}`;
        break;
      }
      case 0x32:
      case 0x33:
      case 0x34:
      case 0x35:
      case 0x36:
      case 0x37: {
        const names = ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"];
        const off = s16();
        line = `${names[op - 0x32]} ${reg(vA4)}, ${reg(vB4)}, ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x38:
      case 0x39:
      case 0x3a:
      case 0x3b:
      case 0x3c:
      case 0x3d: {
        const names = [
          "if-eqz",
          "if-nez",
          "if-ltz",
          "if-gez",
          "if-gtz",
          "if-lez",
        ];
        const off = s16();
        line = `${names[op - 0x38]} ${reg(vAA)}, ${hex((startPc + off) * 2)}`;
        break;
      }
      case 0x44:
      case 0x45:
      case 0x46:
      case 0x47:
      case 0x48:
      case 0x49:
      case 0x4a:
      case 0x4b:
      case 0x4c:
      case 0x4d:
      case 0x4e:
      case 0x4f:
      case 0x50:
      case 0x51: {
        const names = [
          "aget",
          "aget-wide",
          "aget-object",
          "aget-boolean",
          "aget-byte",
          "aget-char",
          "aget-short",
          "aput",
          "aput-wide",
          "aput-object",
          "aput-boolean",
          "aput-byte",
          "aput-char",
          "aput-short",
        ];
        const b = u16();
        line = `${names[op - 0x44]} ${reg(vAA)}, ${reg(b & 0xff)}, ${reg((b >> 8) & 0xff)}`;
        break;
      }
      case 0x52:
      case 0x53:
      case 0x54:
      case 0x55:
      case 0x56:
      case 0x57:
      case 0x58:
      case 0x59:
      case 0x5a:
      case 0x5b:
      case 0x5c:
      case 0x5d:
      case 0x5e:
      case 0x5f: {
        const names = [
          "iget",
          "iget-wide",
          "iget-object",
          "iget-boolean",
          "iget-byte",
          "iget-char",
          "iget-short",
          "iput",
          "iput-wide",
          "iput-object",
          "iput-boolean",
          "iput-byte",
          "iput-char",
          "iput-short",
        ];
        const b = u16();
        line = `${names[op - 0x52]} ${reg(vA4)}, ${reg(vB4)}, ${fld(b)}`;
        break;
      }
      case 0x60:
      case 0x61:
      case 0x62:
      case 0x63:
      case 0x64:
      case 0x65:
      case 0x66:
      case 0x67:
      case 0x68:
      case 0x69:
      case 0x6a:
      case 0x6b:
      case 0x6c:
      case 0x6d: {
        const names = [
          "sget",
          "sget-wide",
          "sget-object",
          "sget-boolean",
          "sget-byte",
          "sget-char",
          "sget-short",
          "sput",
          "sput-wide",
          "sput-object",
          "sput-boolean",
          "sput-byte",
          "sput-char",
          "sput-short",
        ];
        const b = u16();
        line = `${names[op - 0x60]} ${reg(vAA)}, ${fld(b)}`;
        break;
      }
      case 0x6e:
      case 0x6f:
      case 0x70:
      case 0x71:
      case 0x72: {
        const names = [
          "invoke-virtual",
          "invoke-super",
          "invoke-direct",
          "invoke-static",
          "invoke-interface",
        ];
        const methodRef = u16();
        const c = u16();
        const count = vA4;
        const regs = [];
        for (let i = 0; i < count && i < 5; i++)
          regs.push(reg((c >> (i * 4)) & 0xf));
        line = `${names[op - 0x6e]} {${regs.join(", ")}}, ${mth(methodRef)}`;
        break;
      }
      case 0x74:
      case 0x75:
      case 0x76:
      case 0x77:
      case 0x78: {
        const names = [
          "invoke-virtual/range",
          "invoke-super/range",
          "invoke-direct/range",
          "invoke-static/range",
          "invoke-interface/range",
        ];
        const methodRef = u16();
        const c = u16();
        const count = vAA;
        line =
          count > 0
            ? `${names[op - 0x74]} {${reg(c)}..${reg(c + count - 1)}}, ${mth(methodRef)}`
            : `${names[op - 0x74]} {}, ${mth(methodRef)}`;
        break;
      }
      case 0x7b:
      case 0x7c:
      case 0x7d:
      case 0x7e:
      case 0x7f:
      case 0x80:
      case 0x81:
      case 0x82:
      case 0x83:
      case 0x84:
      case 0x85:
      case 0x86:
      case 0x87:
      case 0x88:
      case 0x89:
      case 0x8a:
      case 0x8b:
      case 0x8c:
      case 0x8d:
      case 0x8e:
      case 0x8f: {
        const names = [
          "neg-int",
          "not-int",
          "neg-long",
          "not-long",
          "neg-float",
          "neg-double",
          "int-to-long",
          "int-to-float",
          "int-to-double",
          "long-to-int",
          "long-to-float",
          "long-to-double",
          "float-to-int",
          "float-to-long",
          "float-to-double",
          "double-to-int",
          "double-to-long",
          "double-to-float",
          "int-to-byte",
          "int-to-char",
          "int-to-short",
        ];
        line = `${names[op - 0x7b]} ${reg(vA4)}, ${reg(vB4)}`;
        break;
      }
      case 0x90:
      case 0x91:
      case 0x92:
      case 0x93:
      case 0x94:
      case 0x95:
      case 0x96:
      case 0x97:
      case 0x98:
      case 0x99:
      case 0x9a:
      case 0x9b:
      case 0x9c:
      case 0x9d:
      case 0x9e:
      case 0x9f:
      case 0xa0:
      case 0xa1:
      case 0xa2:
      case 0xa3:
      case 0xa4:
      case 0xa5:
      case 0xa6:
      case 0xa7:
      case 0xa8:
      case 0xa9:
      case 0xaa:
      case 0xab:
      case 0xac:
      case 0xad:
      case 0xae:
      case 0xaf: {
        const names = [
          "add-int",
          "sub-int",
          "mul-int",
          "div-int",
          "rem-int",
          "and-int",
          "or-int",
          "xor-int",
          "shl-int",
          "shr-int",
          "ushr-int",
          "add-long",
          "sub-long",
          "mul-long",
          "div-long",
          "rem-long",
          "and-long",
          "or-long",
          "xor-long",
          "shl-long",
          "shr-long",
          "ushr-long",
          "add-float",
          "sub-float",
          "mul-float",
          "div-float",
          "rem-float",
          "add-double",
          "sub-double",
          "mul-double",
          "div-double",
          "rem-double",
        ];
        const b = u16();
        line = `${names[op - 0x90]} ${reg(vAA)}, ${reg(b & 0xff)}, ${reg((b >> 8) & 0xff)}`;
        break;
      }
      case 0xb0:
      case 0xb1:
      case 0xb2:
      case 0xb3:
      case 0xb4:
      case 0xb5:
      case 0xb6:
      case 0xb7:
      case 0xb8:
      case 0xb9:
      case 0xba:
      case 0xbb:
      case 0xbc:
      case 0xbd:
      case 0xbe:
      case 0xbf:
      case 0xc0:
      case 0xc1:
      case 0xc2:
      case 0xc3:
      case 0xc4:
      case 0xc5:
      case 0xc6:
      case 0xc7:
      case 0xc8:
      case 0xc9:
      case 0xca:
      case 0xcb:
      case 0xcc:
      case 0xcd:
      case 0xce:
      case 0xcf: {
        const names = [
          "add-int/2addr",
          "sub-int/2addr",
          "mul-int/2addr",
          "div-int/2addr",
          "rem-int/2addr",
          "and-int/2addr",
          "or-int/2addr",
          "xor-int/2addr",
          "shl-int/2addr",
          "shr-int/2addr",
          "ushr-int/2addr",
          "add-long/2addr",
          "sub-long/2addr",
          "mul-long/2addr",
          "div-long/2addr",
          "rem-long/2addr",
          "and-long/2addr",
          "or-long/2addr",
          "xor-long/2addr",
          "shl-long/2addr",
          "shr-long/2addr",
          "ushr-long/2addr",
          "add-float/2addr",
          "sub-float/2addr",
          "mul-float/2addr",
          "div-float/2addr",
          "rem-float/2addr",
          "add-double/2addr",
          "sub-double/2addr",
          "mul-double/2addr",
          "div-double/2addr",
          "rem-double/2addr",
        ];
        line = `${names[op - 0xb0]} ${reg(vA4)}, ${reg(vB4)}`;
        break;
      }
      case 0xd0:
      case 0xd1:
      case 0xd2:
      case 0xd3:
      case 0xd4:
      case 0xd5:
      case 0xd6:
      case 0xd7: {
        const names = [
          "add-int/lit16",
          "rsub-int",
          "mul-int/lit16",
          "div-int/lit16",
          "rem-int/lit16",
          "and-int/lit16",
          "or-int/lit16",
          "xor-int/lit16",
        ];
        const b = s16();
        line = `${names[op - 0xd0]} ${reg(vA4)}, ${reg(vB4)}, ${b}`;
        break;
      }
      case 0xd8:
      case 0xd9:
      case 0xda:
      case 0xdb:
      case 0xdc:
      case 0xdd:
      case 0xde:
      case 0xdf:
      case 0xe0:
      case 0xe1:
      case 0xe2: {
        const names = [
          "add-int/lit8",
          "rsub-int/lit8",
          "mul-int/lit8",
          "div-int/lit8",
          "rem-int/lit8",
          "and-int/lit8",
          "or-int/lit8",
          "xor-int/lit8",
          "shl-int/lit8",
          "shr-int/lit8",
          "ushr-int/lit8",
        ];
        const b = u16();
        const lit = b >> 8 > 127 ? (b >> 8) - 256 : b >> 8;
        line = `${names[op - 0xd8]} ${reg(vAA)}, ${reg(b & 0xff)}, ${lit}`;
        break;
      }
      default:
        line = `; unknown opcode ${hex(op)}`;
        break;
    }

    lines.push(`  ${line}`);
  }

  return lines;
}

export interface CFGBlock {
  id: string;
  startPc: number;
  lines: string[];
}

export interface CFGEdgeData {
  from: string;
  to: string;
  type: "true" | "false" | "unconditional";
}

export interface CFGResult {
  blocks: CFGBlock[];
  edges: CFGEdgeData[];
}

/**
 * Build a control flow graph from Dalvik bytecode.
 * Returns basic blocks and edges suitable for visualization.
 */
export function buildCFG(dex: DexFile, method: DexClassMethod): CFGResult {
  if (method.codeOff === 0 || method.codeSize === 0)
    return { blocks: [], edges: [] };

  const dv = dex.data;
  const insnsOff = method.codeOff + 16;
  const insnsSize = method.codeSize;

  // First pass: collect instruction PCs and identify control flow
  interface InsnInfo {
    pc: number;
    op: number;
    targets: number[]; // branch target PCs
    fallsThrough: boolean;
    isBranch: boolean;
    isConditional: boolean;
  }
  const insns: InsnInfo[] = [];
  const leaders = new Set<number>([0]); // block start PCs

  let pc = 0;
  while (pc < insnsSize) {
    const startPc = pc;
    const byteOff = insnsOff + pc * 2;
    const word = dv.getUint16(byteOff, true);
    const op = word & 0xff;
    const vAA = (word >> 8) & 0xff;

    const info: InsnInfo = {
      pc: startPc,
      op,
      targets: [],
      fallsThrough: true,
      isBranch: false,
      isConditional: false,
    };

    if (op >= 0x0e && op <= 0x11) {
      // return-void, return, return-wide, return-object
      info.fallsThrough = false;
    } else if (op === 0x27) {
      // throw
      info.fallsThrough = false;
    } else if (op === 0x28) {
      // goto
      const off = vAA > 127 ? vAA - 256 : vAA;
      info.targets.push(startPc + off);
      info.fallsThrough = false;
      info.isBranch = true;
    } else if (op === 0x29) {
      // goto/16
      const raw = dv.getUint16(insnsOff + (pc + 1) * 2, true);
      const off = raw > 0x7fff ? raw - 0x10000 : raw;
      info.targets.push(startPc + off);
      info.fallsThrough = false;
      info.isBranch = true;
    } else if (op === 0x2a) {
      // goto/32
      const lo = dv.getUint16(insnsOff + (pc + 1) * 2, true);
      const hi = dv.getUint16(insnsOff + (pc + 2) * 2, true);
      let off = (hi << 16) | lo;
      if (off > 0x7fffffff) off -= 0x100000000;
      info.targets.push(startPc + off);
      info.fallsThrough = false;
      info.isBranch = true;
    } else if (op >= 0x32 && op <= 0x37) {
      // if-eq ... if-le (two register)
      const raw = dv.getUint16(insnsOff + (pc + 1) * 2, true);
      const off = raw > 0x7fff ? raw - 0x10000 : raw;
      info.targets.push(startPc + off);
      info.fallsThrough = true;
      info.isBranch = true;
      info.isConditional = true;
    } else if (op >= 0x38 && op <= 0x3d) {
      // if-eqz ... if-lez (one register)
      const raw = dv.getUint16(insnsOff + (pc + 1) * 2, true);
      const off = raw > 0x7fff ? raw - 0x10000 : raw;
      info.targets.push(startPc + off);
      info.fallsThrough = true;
      info.isBranch = true;
      info.isConditional = true;
    } else if (op === 0x2b || op === 0x2c) {
      // packed-switch / sparse-switch
      const lo = dv.getUint16(insnsOff + (pc + 1) * 2, true);
      const hi = dv.getUint16(insnsOff + (pc + 2) * 2, true);
      let tableOff = (hi << 16) | lo;
      if (tableOff > 0x7fffffff) tableOff -= 0x100000000;
      const tableAddr = startPc + tableOff;
      const tableByteOff = insnsOff + tableAddr * 2;
      if (tableByteOff >= 0 && tableByteOff + 4 < dv.byteLength) {
        const ident = dv.getUint16(tableByteOff, true);
        const size = dv.getUint16(tableByteOff + 2, true);
        if (ident === 0x0100) {
          // packed-switch: targets start at offset 4 (after ident + size + first_key)
          for (let i = 0; i < size; i++) {
            const tOff = tableByteOff + 8 + i * 4;
            if (tOff + 4 <= dv.byteLength) {
              let rel = dv.getInt32(tOff, true);
              info.targets.push(startPc + rel);
            }
          }
        } else if (ident === 0x0200) {
          // sparse-switch: keys then targets
          for (let i = 0; i < size; i++) {
            const tOff = tableByteOff + 4 + size * 4 + i * 4;
            if (tOff + 4 <= dv.byteLength) {
              let rel = dv.getInt32(tOff, true);
              info.targets.push(startPc + rel);
            }
          }
        }
      }
      info.fallsThrough = true;
      info.isBranch = true;
      info.isConditional = true;
    }

    // Mark leaders
    for (const t of info.targets) {
      if (t >= 0 && t < insnsSize) leaders.add(t);
    }
    insns.push(info);
    pc = startPc + opcodeWidth(op);

    // Instruction after a branch is a leader
    if (info.isBranch || !info.fallsThrough) {
      if (pc < insnsSize) leaders.add(pc);
    }
  }

  // Get disassembly text (one line per instruction)
  const textLines = disassembleMethod(dex, method);

  // Build blocks
  const sortedLeaders = [...leaders].sort((a, b) => a - b);
  const pcToBlockId = new Map<number, string>();
  for (const l of sortedLeaders) {
    pcToBlockId.set(l, `bb_${("0000" + (l * 2).toString(16)).slice(-4)}`);
  }

  const blocks: CFGBlock[] = [];
  const edges: CFGEdgeData[] = [];

  for (let bi = 0; bi < sortedLeaders.length; bi++) {
    const blockStart = sortedLeaders[bi];
    const blockEnd = bi + 1 < sortedLeaders.length ? sortedLeaders[bi + 1] : insnsSize;
    const blockId = pcToBlockId.get(blockStart)!;

    // Collect instructions in this block
    const blockInsns = insns.filter((ins) => ins.pc >= blockStart && ins.pc < blockEnd);
    // Collect corresponding text lines
    const startIdx = insns.indexOf(blockInsns[0]);
    const blockLines = textLines.slice(startIdx, startIdx + blockInsns.length).map((l) => l.trim());

    blocks.push({
      id: blockId,
      startPc: blockStart,
      lines: blockLines,
    });

    if (blockInsns.length === 0) continue;
    const lastInsn = blockInsns[blockInsns.length - 1];

    // Add edges
    if (lastInsn.isConditional) {
      // True branch (first target)
      for (const t of lastInsn.targets) {
        const targetId = pcToBlockId.get(t);
        if (targetId) edges.push({ from: blockId, to: targetId, type: "true" });
      }
      // Fall-through (false branch)
      if (lastInsn.fallsThrough) {
        const nextPc = lastInsn.pc + opcodeWidth(lastInsn.op);
        const targetId = pcToBlockId.get(nextPc);
        if (targetId) edges.push({ from: blockId, to: targetId, type: "false" });
      }
    } else if (lastInsn.isBranch) {
      // Unconditional goto
      for (const t of lastInsn.targets) {
        const targetId = pcToBlockId.get(t);
        if (targetId) edges.push({ from: blockId, to: targetId, type: "unconditional" });
      }
    } else if (lastInsn.fallsThrough) {
      // Normal fall-through
      const nextPc = lastInsn.pc + opcodeWidth(lastInsn.op);
      const targetId = pcToBlockId.get(nextPc);
      if (targetId) edges.push({ from: blockId, to: targetId, type: "unconditional" });
    }
  }

  return { blocks, edges };
}

/**
 * Find all methods that reference a given string index via
 * const-string (0x1a) or const-string/jumbo (0x1b).
 */
export function findStringXrefs(dex: DexFile, stringIdx: number): StringXref[] {
  const results: StringXref[] = [];
  const dv = dex.data;

  for (const cls of dex.classes) {
    const allMethods = [...cls.directMethods, ...cls.virtualMethods];
    for (const method of allMethods) {
      if (method.codeOff === 0 || method.codeSize === 0) continue;

      const insnsOff = method.codeOff + 16;
      const insnsSize = method.codeSize;
      let pc = 0;

      while (pc < insnsSize) {
        const byteOff = insnsOff + pc * 2;
        const word = dv.getUint16(byteOff, true);
        const op = word & 0xff;

        if (op === 0x1a) {
          // const-string vAA, string@BBBB — next u16 is the string index
          if (pc + 1 < insnsSize) {
            const idx = dv.getUint16(byteOff + 2, true);
            if (idx === stringIdx) {
              results.push({
                className: cls.className,
                methodName: method.name,
                methodIdx: method.methodIdx,
                codeOffset: pc * 2,
              });
            }
          }
          pc += 2;
        } else if (op === 0x1b) {
          // const-string/jumbo vAA, string@BBBBBBBB — next u32 is the index
          if (pc + 2 < insnsSize) {
            const lo = dv.getUint16(byteOff + 2, true);
            const hi = dv.getUint16(byteOff + 4, true);
            const idx = (hi << 16) | lo;
            if (idx === stringIdx) {
              results.push({
                className: cls.className,
                methodName: method.name,
                methodIdx: method.methodIdx,
                codeOffset: pc * 2,
              });
            }
          }
          pc += 3;
        } else {
          // Skip instruction based on opcode format width
          pc += opcodeWidth(op);
        }
      }
    }
  }

  return results;
}

/** Returns instruction width in 16-bit code units for a given opcode. */
function opcodeWidth(op: number): number {
  if (op === 0x00) return 1; // nop (also covers pseudo-ops but we only care about skipping)
  if (op <= 0x01) return 1;
  if (op <= 0x02) return 2;
  if (op === 0x03) return 3;
  if (op <= 0x05) return 2;
  if (op === 0x06) return 3;
  if (op <= 0x08) return 2;
  if (op === 0x09) return 3;
  if (op <= 0x12) return 1;
  if (op <= 0x15) return 2;
  if (op <= 0x17) return 2;
  if (op === 0x18) return 5;
  if (op <= 0x1a) return 2;
  if (op === 0x1b) return 3;
  if (op === 0x1c) return 2;
  if (op <= 0x1e) return 1;
  if (op <= 0x20) return 2;
  if (op === 0x21) return 1;
  if (op <= 0x25) return 2;
  if (op === 0x26) return 3;
  if (op === 0x27) return 1;
  if (op === 0x28) return 1;
  if (op === 0x29) return 2;
  if (op === 0x2a) return 3;
  if (op <= 0x2c) return 3;
  if (op <= 0x31) return 2;
  if (op <= 0x37) return 2;
  if (op <= 0x3d) return 2;
  if (op <= 0x43) return 1; // unused
  if (op <= 0x51) return 2;
  if (op <= 0x6d) return 2;
  if (op <= 0x72) return 3;
  if (op === 0x73) return 1; // unused
  if (op <= 0x78) return 3;
  if (op <= 0x7a) return 1; // unused
  if (op <= 0x8f) return 1;
  if (op <= 0xaf) return 2;
  if (op <= 0xcf) return 1;
  if (op <= 0xe2) return 2;
  return 1; // unknown — skip 1 to avoid infinite loop
}
