import { List, type RowComponentProps } from "react-window";

export type Stride = 8 | 16 | 32 | 64;

interface HexViewParams {
  data: Uint8Array;
  stride: Stride;
}

export default function HexView({ data, stride }: HexViewParams) {
  const count = Math.ceil(data.byteLength / stride);

  return (
    <List
      rowComponent={HexRow}
      rowCount={count}
      rowHeight={24}
      rowProps={{ data, stride }}
    />
  );
}

function printable(value: number) {
  return value >= 32 && value <= 126 ? String.fromCharCode(value) : ".";
}

function HexRow({
  index,
  data,
  stride,
  style,
}: RowComponentProps<{
  data: Uint8Array;
  stride: Stride;
}>) {
  const start = index * stride;
  const end = Math.min(start + stride);
  const chunk = Array.from(data.slice(start, end));
  const offset = start.toString(16).padStart(8, "0");
  const w = stride * 3 - 1;
  const xxd = chunk.map((val) => val.toString(16).padStart(2, "0"));
  const hexColumn = xxd.join(" ").padEnd(w, " ");
  const ascii = chunk.map(printable).join("");

  return (
    <div className="flex items-start leading-6 text-sm gap-4" style={style}>
      <code className="text-green-500">{offset}</code>
      <code className="whitespace-pre">{hexColumn}</code>
      <code className="whitespace-pre">{ascii}</code>
    </div>
  );
}
