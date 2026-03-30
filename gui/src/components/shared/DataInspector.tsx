import { useMemo } from "react";

interface Props {
  bytes: Uint8Array | null;
  offset: number;
}

interface Row {
  label: string;
  le: string;
  be?: string;
}

export default function DataInspector({ bytes, offset }: Props) {
  const rows = useMemo(() => inspect(bytes), [bytes]);

  if (!bytes || bytes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground text-xs">
        Click a byte to inspect
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-2">
      <div className="text-xs text-muted-foreground mb-2 font-mono">
        Offset: 0x{offset.toString(16).padStart(8, "0")}
      </div>
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="text-muted-foreground">
            <th className="text-left font-normal pr-3 pb-1">Type</th>
            <th className="text-right font-normal pr-3 pb-1">LE</th>
            <th className="text-right font-normal pb-1">BE</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label} className="border-t border-border/40">
              <td className="text-muted-foreground pr-3 py-0.5">{r.label}</td>
              <td className="text-right pr-3 py-0.5">{r.le}</td>
              <td className="text-right py-0.5">{r.be ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function inspect(bytes: Uint8Array | null): Row[] {
  if (!bytes || bytes.length === 0) return [];

  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const le = new DataView(buf);
  const rows: Row[] = [];
  const n = bytes.length;

  rows.push({ label: "UInt8", le: le.getUint8(0).toString() });
  rows.push({ label: "Int8", le: le.getInt8(0).toString() });

  if (n >= 2) {
    rows.push({ label: "UInt16", le: le.getUint16(0, true).toString(), be: le.getUint16(0, false).toString() });
    rows.push({ label: "Int16", le: le.getInt16(0, true).toString(), be: le.getInt16(0, false).toString() });
  }

  if (n >= 4) {
    rows.push({ label: "UInt32", le: le.getUint32(0, true).toString(), be: le.getUint32(0, false).toString() });
    rows.push({ label: "Int32", le: le.getInt32(0, true).toString(), be: le.getInt32(0, false).toString() });
    rows.push({
      label: "Float32",
      le: fmt(le.getFloat32(0, true)),
      be: fmt(le.getFloat32(0, false)),
    });
  }

  if (n >= 8) {
    rows.push({ label: "UInt64", le: le.getBigUint64(0, true).toString(), be: le.getBigUint64(0, false).toString() });
    rows.push({ label: "Int64", le: le.getBigInt64(0, true).toString(), be: le.getBigInt64(0, false).toString() });
    rows.push({
      label: "Float64",
      le: fmt(le.getFloat64(0, true)),
      be: fmt(le.getFloat64(0, false)),
    });
  }

  // Binary representation of first byte
  rows.push({ label: "Binary", le: le.getUint8(0).toString(2).padStart(8, "0") });

  // UTF-8 decode
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(0, 16));
    const display = text.replace(/[\x00-\x1f\x7f-\x9f]/g, "·");
    rows.push({ label: "UTF-8", le: display });
  } catch {
    rows.push({ label: "UTF-8", le: "(invalid)" });
  }

  return rows;
}

function fmt(v: number): string {
  if (Number.isNaN(v)) return "NaN";
  if (!Number.isFinite(v)) return v > 0 ? "Inf" : "-Inf";
  return v.toPrecision(7);
}

