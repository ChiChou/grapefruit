import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";
import { drainInputStream } from "@/droid/lib/jbytes.js";

let cached: string | null = null;

export function xml() {
  return perform(() => {
    if (cached !== null) return cached;
    const manifest = readManifestXml();
    cached = manifest;
    return manifest;
  });
}

function readManifestXml(): string {
  const context = getContext();
  const sourceDir: string = context.getApplicationInfo().sourceDir.value;

  const ZipFile = Java.use("java.util.zip.ZipFile");
  const zip = ZipFile.$new(sourceDir);

  try {
    const entry = zip.getEntry("AndroidManifest.xml");
    if (!entry) throw new Error("AndroidManifest.xml not found in APK");

    const inputStream = zip.getInputStream(entry);
    const data = drainInputStream(inputStream);
    inputStream.close();

    return decodeAxml(data);
  } finally {
    zip.close();
  }
}

/**
 * Decodes a binary AndroidManifest.xml (AXML) into plain text XML.
 * Pure JS implementation using DataView — no Java bridge calls during parsing.
 */
function decodeAxml(data: ArrayBuffer): string {
  const dv = new DataView(data);
  const u8 = new Uint8Array(data);
  const length = data.byteLength;

  const readInt = (offset: number): number => dv.getInt32(offset, true);
  const readShort = (offset: number): number => dv.getUint16(offset, true);

  const END_DOC_TAG = 0x00100101;
  const START_TAG = 0x00100102;
  const END_TAG = 0x00100103;

  const numStrings = readInt(16);
  const stringIndexTableOffset = 0x24;
  const stringDataTableOffset = stringIndexTableOffset + numStrings * 4;

  const getString = (strIndex: number): string | null => {
    if (strIndex < 0) return null;

    const indexOffset = stringIndexTableOffset + strIndex * 4;
    const offsetInData = readInt(indexOffset);
    const strAbsOffset = stringDataTableOffset + offsetInData;
    const strLen = readShort(strAbsOffset);

    if (strLen === 0) return "";

    // Decode UTF-16LE in pure JS
    const start = strAbsOffset + 2;
    const byteOff = u8.byteOffset + start;
    if (byteOff % 2 === 0) {
      const codes = new Uint16Array(u8.buffer, byteOff, strLen);
      return String.fromCharCode(...codes);
    }
    // Unaligned fallback: read code units via DataView
    const chars: number[] = new Array(strLen);
    for (let i = 0; i < strLen; i++) {
      chars[i] = readShort(start + i * 2);
    }
    return String.fromCharCode(...chars);
  };

  let xmlTagOffset = readInt(12);
  for (let i = xmlTagOffset; i < length - 4; i += 4) {
    if (readInt(i) === START_TAG) {
      xmlTagOffset = i;
      break;
    }
  }

  let offset = xmlTagOffset;
  let indent = 0;
  const sb: string[] = [];

  while (offset < length) {
    const tag0 = readInt(offset);
    const nameSi = readInt(offset + 20);

    if (tag0 === START_TAG) {
      const attrCount = readInt(offset + 28);
      offset += 36;

      const elemName = getString(nameSi);
      let attrStr = "";

      for (let a = 0; a < attrCount; a++) {
        const attrNameSi = readInt(offset + 4);
        const attrValueSi = readInt(offset + 8);
        const attrResId = readInt(offset + 16);
        offset += 20;

        const attrName = getString(attrNameSi);
        let attrValue: string;

        if (attrValueSi !== -1) {
          attrValue = getString(attrValueSi) || "";
        } else {
          attrValue =
            "0x" +
            (attrResId >>> 0).toString(16).toUpperCase().padStart(8, "0");
        }

        attrValue = attrValue.replace(/"/g, "&quot;");
        attrStr += ` ${attrName}="${attrValue}"`;
      }

      const padding = "  ".repeat(indent);
      sb.push(`${padding}<${elemName}${attrStr}>`);
      indent++;
    } else if (tag0 === END_TAG) {
      indent--;
      const elemName = getString(nameSi);
      offset += 24;

      const padding = "  ".repeat(indent);
      sb.push(`${padding}</${elemName}>`);
    } else if (tag0 === END_DOC_TAG) {
      break;
    } else {
      break;
    }
  }

  return sb.join("\n");
}
