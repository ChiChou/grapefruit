import { useRef, type RefObject } from "react";
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";

const ROW_HEIGHT = 32;

export function LogTable<T extends { id: number }>({
  data,
  columns,
  selectedId,
  onSelect,
  scrollRef,
}: {
  data: T[];
  columns: ColumnDef<T>[];
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  scrollRef?: RefObject<HTMLDivElement | null>;
}) {
  const internalRef = useRef<HTMLDivElement>(null);
  const containerRef = scrollRef ?? internalRef;

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => String(row.id),
  });

  const { rows } = table.getRowModel();

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();

  return (
    <div ref={containerRef} className="flex-1 overflow-auto">
      <table className="w-full text-xs border-collapse">
        <thead className="sticky top-0 bg-background z-10">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id} className="border-b">
              {headerGroup.headers.map((header) => (
                <th
                  key={header.id}
                  className="text-left font-medium p-2 text-muted-foreground"
                  style={{ width: header.getSize() }}
                >
                  {flexRender(
                    header.column.columnDef.header,
                    header.getContext(),
                  )}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {virtualRows.length > 0 && virtualRows[0].start > 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{ height: virtualRows[0].start }}
              />
            </tr>
          )}
          {virtualRows.map((virtualRow) => {
            const row = rows[virtualRow.index];
            return (
              <tr
                key={row.id}
                className={`border-b cursor-pointer hover:bg-muted/50 ${
                  selectedId === row.original.id ? "bg-accent" : ""
                }`}
                style={{ height: virtualRow.size }}
                onClick={() =>
                  onSelect(
                    selectedId === row.original.id ? null : row.original.id,
                  )
                }
              >
                {row.getVisibleCells().map((cell) => (
                  <td
                    key={cell.id}
                    className="p-2 truncate"
                    style={{
                      width: cell.column.getSize(),
                      maxWidth: cell.column.getSize(),
                    }}
                  >
                    {flexRender(
                      cell.column.columnDef.cell,
                      cell.getContext(),
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
          {virtualRows.length > 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{
                  height:
                    totalSize -
                    (virtualRows[virtualRows.length - 1]?.end ?? 0),
                }}
              />
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
