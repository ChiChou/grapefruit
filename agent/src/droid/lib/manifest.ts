import Java from "frida-java-bridge";

import { getContext } from "./context.js";

/**
 * Decodes a binary AndroidManifest.xml (AXML) into plain text XML.
 */
function decodeAxml(input: Uint8Array): string {
  const readInt = (offset: number): number => {
    return (
      input[offset] |
      (input[offset + 1] << 8) |
      (input[offset + 2] << 16) |
      (input[offset + 3] << 24)
    );
  };

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
    const strLen = input[strAbsOffset] | (input[strAbsOffset + 1] << 8);

    let str = "";
    for (let i = 0; i < strLen; i++) {
      const charOffset = strAbsOffset + 2 + i * 2;
      const charCode = input[charOffset] | (input[charOffset + 1] << 8);
      str += String.fromCharCode(charCode);
    }
    return str;
  };

  let xmlTagOffset = readInt(12);
  for (let i = xmlTagOffset; i < input.length - 4; i += 4) {
    if (readInt(i) === START_TAG) {
      xmlTagOffset = i;
      break;
    }
  }

  let offset = xmlTagOffset;
  let indent = 0;
  const sb: string[] = [];

  while (offset < input.length) {
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

/**
 * Reads and decodes AndroidManifest.xml from the current app's APK.
 */
export function readManifestXml(): string {
  const context = getContext();
  const sourceDir: string = context.getApplicationInfo().sourceDir.value;

  const ZipFile = Java.use("java.util.zip.ZipFile");
  const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

  const zip = ZipFile.$new(sourceDir);
  try {
    const entry = zip.getEntry("AndroidManifest.xml");
    if (!entry) throw new Error("AndroidManifest.xml not found in APK");

    const inputStream = zip.getInputStream(entry);
    const outputStream = ByteArrayOutputStream.$new();
    const buffer = Java.array("byte", new Array(4096).fill(0));
    let len: number;

    while ((len = inputStream.read(buffer)) !== -1) {
      outputStream.write(buffer, 0, len);
    }
    inputStream.close();

    const manifestBytes = outputStream.toByteArray();
    const jsBytes = new Uint8Array(manifestBytes.length);
    for (let i = 0; i < manifestBytes.length; i++) {
      jsBytes[i] = manifestBytes[i];
    }

    return decodeAxml(jsBytes);
  } finally {
    zip.close();
  }
}
