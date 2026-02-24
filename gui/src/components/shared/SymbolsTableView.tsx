import { useMemo, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { Search, FileCode, Database, Anchor, Code } from "lucide-react";
import { Spinner } from "@/components/ui/spinner";
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  flexRender,
  type ColumnDef,
  type ColumnResizeMode,
  type RowSelectionState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { useDock } from "@/context/DockContext";
import { useSession, Status, Mode, Platform } from "@/context/SessionContext";
import { useRepl } from "@/context/useRepl";
import { native, type NativeHookTarget } from "@/lib/hook-template";
import { NativeHookDialog } from "@/components/shared/NativeHookDialog";

import type { Symbol, Exported } from "@agent/common/symbol";

export type SymbolItem = Symbol | Exported;

interface SymbolsTableViewProps {
  symbols: SymbolItem[] | null;
  loading: boolean;
  modulePath?: string;
  selectable?: boolean;
}

const DEFAULT_WIDTHS = {
  select: 32,
  actions: 60,
  type: 32,
  name: 300,
  address: 140,
  demangled: 400,
};

export function SymbolsTableView({
  symbols,
  loading,
  modulePath,
  selectable = true,
}: SymbolsTableViewProps) {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const { fruity, droid, status, platform, mode, device, bundle, pid, fridaMajor } = useSession();
  const api = platform === Platform.Droid ? droid : fruity;
  const { appendCode } = useRepl();
  const navigate = useNavigate();

  const hooksPath = `/workspace/${platform}/${device}/${mode}/${mode === Mode.App ? bundle : pid}/hooks`;
  const [globalFilter, setGlobalFilter] = useState("");
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [hookDialogOpen, setHookDialogOpen] = useState(false);
  const [hookDialogTarget, setHookDialogTarget] = useState<SymbolItem | null>(null);
  const [columnSizing, setColumnSizing] = useState<Record<string, number>>({
    select: DEFAULT_WIDTHS.select,
    actions: DEFAULT_WIDTHS.actions,
    type: DEFAULT_WIDTHS.type,
    name: DEFAULT_WIDTHS.name,
    address: DEFAULT_WIDTHS.address,
    demangled: DEFAULT_WIDTHS.demangled,
  });
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const openDisassemblyTab = useCallback(
    (address: string, name?: string) => {
      openFilePanel({
        id: `disasm_${address}`,
        component: "disassembly",
        title: name ? `${name}` : address,
        params: { address, name },
      });
    },
    [openFilePanel],
  );

  const openClassTab = useCallback(
    (className: string) => {
      openFilePanel({
        id: `class_${className}`,
        component: "classDetail",
        title: className,
        params: { className },
      });
    },
    [openFilePanel],
  );

  const handleAddressClick = useCallback(
    (item: SymbolItem) => {
      // Check if it's an ObjC class reference
      if (item.name.startsWith("OBJC_CLASS_$_")) {
        const className = item.name.replace("OBJC_CLASS_$_", "");
        openClassTab(className);
        return;
      }
      // Open disassembly if clickable (already validated by isClickable)
      if (item.addr) {
        openDisassemblyTab(item.addr, item.name);
      }
    },
    [openClassTab, openDisassemblyTab],
  );

  const isClickable = useCallback((item: SymbolItem): boolean => {
    // ObjC class references are always clickable
    if (item.name.startsWith("OBJC_CLASS_$_")) return true;
    // No address means not clickable
    if (!item.addr) return false;
    // Check if item has type info (Exported/Imported types have this)
    const typed = item as Exported;
    if (typed.type !== undefined) {
      // Only functions are clickable for disassembly
      return typed.type === "f";
    }
    // For Symbol type (no type field), assume it's clickable
    return true;
  }, []);

  const isFunction = useCallback((item: SymbolItem): boolean => {
    const typed = item as Exported;
    return typed.type === "f";
  }, []);

  const data = useMemo(() => symbols ?? [], [symbols]);

  const handleHookFunction = useCallback(
    (item: SymbolItem) => {
      if (!api || status !== Status.Ready) return;
      setHookDialogTarget(item);
      setHookDialogOpen(true);
    },
    [api, status],
  );

  const handleHookConfirm = useCallback(
    async (sig: { args: string[]; returns: string }) => {
      if (!api || !hookDialogTarget) return;
      try {
        await api.native.hook(modulePath ?? null, hookDialogTarget.name, sig);
        navigate(hooksPath);
        toast.success(t("hook_added"), {
          description: modulePath
            ? `${modulePath}!${hookDialogTarget.name}`
            : hookDialogTarget.name,
        });
        window.dispatchEvent(new CustomEvent("hooks:refresh"));
      } catch (error) {
        console.error("Failed to hook function:", error);
        toast.error(t("hook_failed"));
      }
    },
    [api, hookDialogTarget, modulePath, navigate, hooksPath, t],
  );

  const handleGenerateCode = useCallback(
    (item: SymbolItem) => {
      const target: NativeHookTarget = {
        type: "native",
        module: modulePath ?? null,
        name: item.name,
      };
      const code = native(target, fridaMajor);
      appendCode(code);
    },
    [modulePath, appendCode, fridaMajor],
  );

  const handleBatchGenerateCode = useCallback(() => {
    const selectedIndices = Object.keys(rowSelection).filter(
      (key) => rowSelection[key],
    );
    const selectedItems = selectedIndices
      .map((idx) => data[parseInt(idx)])
      .filter((item) => item && isFunction(item));

    const codes = selectedItems.map((item) => {
      const target: NativeHookTarget = {
        type: "native",
        module: modulePath ?? null,
        name: item.name,
      };
      return native(target, fridaMajor);
    });

    if (codes.length > 0) {
      appendCode(codes.join("\n"));
    }
  }, [rowSelection, data, modulePath, appendCode, isFunction, fridaMajor]);

  const columns = useMemo<ColumnDef<SymbolItem>[]>(() => {
    const cols: ColumnDef<SymbolItem>[] = [];

    if (selectable) {
      cols.push({
        id: "select",
        header: "",
        size: 90,
        minSize: 90,
        cell: ({ row }) => {
          const item = row.original;
          if (!isFunction(item)) return <span className="h-4 w-4" />;
          return (
            <div className="flex items-center gap-1">
              <Checkbox
                checked={row.getIsSelected()}
                onCheckedChange={(value) => row.toggleSelected(!!value)}
                aria-label="Select row"
                className="shrink-0"
              />
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={() => handleHookFunction(item)}
                disabled={status !== Status.Ready}
                title={t("hook_add")}
              >
                <Anchor className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={() => handleGenerateCode(item)}
                title={t("hook_generate_code")}
              >
                <Code className="h-3.5 w-3.5" />
              </Button>
            </div>
          );
        },
        enableResizing: false,
      });
    }

    cols.push(
      {
        id: "type",
        header: "",
        size: DEFAULT_WIDTHS.type,
        minSize: 32,
        maxSize: 50,
        cell: ({ row }) => {
          const item = row.original as Exported;
          if (item.type === "f") {
            return <FileCode className="w-3.5 h-3.5 text-amber-500" />;
          } else if (item.type === "v") {
            return <Database className="w-3.5 h-3.5 text-green-500" />;
          }
          return null;
        },
      },
      {
        accessorKey: "name",
        header: () => t("name"),
        size: DEFAULT_WIDTHS.name,
        minSize: 100,
      },
      {
        accessorKey: "addr",
        header: () => t("address"),
        size: DEFAULT_WIDTHS.address,
        minSize: 80,
        cell: ({ row }) => {
          const item = row.original;
          const addr = item.addr;
          if (!addr) return "-";
          if (isClickable(item)) {
            return (
              <button
                type="button"
                className="text-amber-600 dark:text-amber-400 hover:underline cursor-pointer"
                onClick={() => handleAddressClick(item)}
              >
                {addr}
              </button>
            );
          }
          return <span className="text-muted-foreground">{addr}</span>;
        },
      },
      {
        accessorKey: "demangled",
        header: () => t("demangled"),
        size: DEFAULT_WIDTHS.demangled,
        minSize: 100,
        cell: ({ getValue }) => getValue() || "-",
      },
    );

    return cols;
  }, [
    t,
    handleAddressClick,
    isClickable,
    isFunction,
    handleHookFunction,
    handleGenerateCode,
    status,
    selectable,
  ]);

  const table = useReactTable({
    data,
    columns,
    state: {
      globalFilter,
      columnSizing,
      rowSelection,
    },
    onGlobalFilterChange: setGlobalFilter,
    onColumnSizingChange: setColumnSizing,
    onRowSelectionChange: setRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    columnResizeMode: "onChange" as ColumnResizeMode,
    enableColumnResizing: true,
    enableRowSelection: selectable ? (row) => isFunction(row.original) : false,
  });

  const { rows } = table.getRowModel();

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 32,
    overscan: 20,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();

  const selectedCount = Object.keys(rowSelection).filter(
    (key) => rowSelection[key],
  ).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
        <Spinner />
        {t("loading")}...
      </div>
    );
  }

  if (!symbols || symbols.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <NativeHookDialog
        open={hookDialogOpen}
        onOpenChange={setHookDialogOpen}
        functionName={hookDialogTarget?.name ?? ""}
        modulePath={modulePath ?? null}
        onConfirm={handleHookConfirm}
      />
      <div className="flex items-center gap-2 mb-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("search")}
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {selectable && (
        <div className="flex items-center gap-2 mb-2">
          <Checkbox
            checked={table.getIsAllPageRowsSelected()}
            indeterminate={table.getIsSomePageRowsSelected()}
            onCheckedChange={(value) =>
              table.toggleAllPageRowsSelected(!!value)
            }
            aria-label="Select all"
            className="shrink-0"
          />
          <Button
            variant="outline"
            size="sm"
            onClick={handleBatchGenerateCode}
            disabled={selectedCount === 0}
            className="gap-1.5"
          >
            <Code className="h-4 w-4" />
            {t("hook_batch_generate")}
          </Button>
          {selectedCount > 0 && (
            <span className="text-sm text-muted-foreground">
              {t("hook_selected_count", { count: selectedCount })}
            </span>
          )}
        </div>
      )}

      <div className="text-xs text-muted-foreground mb-1">
        {rows.length.toLocaleString()} / {data.length.toLocaleString()}{" "}
        {t("items")}
      </div>
      <div ref={tableContainerRef} className="overflow-auto flex-1">
        <table
          className="w-full text-sm border-collapse"
          style={{ width: table.getCenterTotalSize() }}
        >
          <thead className="sticky top-0 bg-background z-10">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="relative text-left font-medium p-2 select-none"
                    style={{ width: header.getSize() }}
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                    {header.column.getCanResize() && (
                      <div
                        onMouseDown={header.getResizeHandler()}
                        onTouchStart={header.getResizeHandler()}
                        className={`absolute right-0 top-0 h-full w-1 cursor-col-resize select-none touch-none hover:bg-amber-500/50 ${
                          header.column.getIsResizing() ? "bg-amber-500" : ""
                        }`}
                      />
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {/* Spacer for virtual scroll */}
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
                  key={virtualRow.index}
                  className="border-b hover:bg-muted/50 group"
                  style={{ height: virtualRow.size }}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="p-2 font-mono text-xs truncate"
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
            {/* Spacer for virtual scroll end */}
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
    </div>
  );
}
