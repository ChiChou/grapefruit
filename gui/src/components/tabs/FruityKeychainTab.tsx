import { useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import {
  RefreshCw,
  Trash2,
  Key,
  User,
  Server,
  ChevronDown,
  ChevronRight,
  Download,
  Copy,
  Check,
  ChevronsDownUp,
  ChevronsUpDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Spinner } from "@/components/ui/spinner";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useRpcQuery, useRpcMutation, useQueryClient } from "@/lib/queries";
import {
  useReactTable,
  getCoreRowModel,
  getExpandedRowModel,
  flexRender,
  type ColumnDef,
  type ColumnResizeMode,
  type ExpandedState,
} from "@tanstack/react-table";

import type { KeyChainItem } from "@agent/fruity/modules/keychain";

function formatBoolean(value: boolean | undefined): string {
  return value ? "✓" : "-";
}

function hexDump(base64Data: string | undefined): string {
  if (!base64Data) return "";

  try {
    const binaryString = atob(base64Data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const lines: string[] = [];
    const bytesPerLine = 16;

    for (let offset = 0; offset < bytes.length; offset += bytesPerLine) {
      const lineBytes = bytes.slice(offset, offset + bytesPerLine);
      const hexPart = Array.from(lineBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      const asciiPart = Array.from(lineBytes)
        .map((b) => {
          const char = String.fromCharCode(b);
          return b >= 32 && b <= 126 ? char : ".";
        })
        .join("");

      const offsetHex = offset.toString(16).padStart(8, "0");
      lines.push(`${offsetHex}  ${hexPart.padEnd(47, " ")}  |${asciiPart}|`);
    }

    return lines.join("\n");
  } catch {
    return "<invalid base64>";
  }
}

export function FruityKeychainTab() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [withBiometricId, setWithBiometricId] = useState(false);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [copySuccessIndex, setCopySuccessIndex] = useState<string | null>(null);
  const [classFilterOpen, setClassFilterOpen] = useState(false);
  const [protFilterOpen, setProtFilterOpen] = useState(false);
  const [selectedClasses, setSelectedClasses] = useState<Set<string>>(
    new Set(),
  );
  const [selectedProts, setSelectedProts] = useState<Set<string>>(new Set());
  const [columnSizing, setColumnSizing] = useState<Record<string, number>>({});

  const {
    data: items = [],
    isLoading,
    refetch,
  } = useRpcQuery<KeyChainItem[]>(
    ["keychain", String(withBiometricId)],
    (api) => api.keychain.list(withBiometricId),
  );

  const removeMutation = useRpcMutation<
    void,
    { service: string; account: string }
  >((api, { service, account }) => api.keychain.remove(service, account), {
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["keychain"] });
    },
  });

  const handleDelete = async (item: KeyChainItem) => {
    const service = item.service || "";
    const account = item.account || "";
    await removeMutation.mutateAsync({ service, account });
  };

  const downloadRaw = (item: KeyChainItem) => {
    if (!item.raw) return;
    try {
      const binaryString = atob(item.raw);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const filename = `${item.service || "unknown"}-${item.account || "unknown"}.bin`;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch {
      console.error("Failed to download raw data");
    }
  };

  const copyToClipboardRaw = async (item: KeyChainItem, rowId: string) => {
    if (!item.raw) return;
    try {
      const binaryString = atob(item.raw);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const decoder = new TextDecoder("utf-8", { fatal: false });
      const text = decoder.decode(bytes);
      await navigator.clipboard.writeText(text);
      setCopySuccessIndex(rowId);
      setTimeout(() => setCopySuccessIndex(null), 2000);
    } catch {
      console.error("Failed to copy raw data to clipboard");
    }
  };

  const allClasses = Array.from(
    new Set(items.map((i) => i.clazz).filter(Boolean) as string[]),
  );
  const allProts = Array.from(
    new Set(items.map((i) => i.prot).filter(Boolean) as string[]),
  );

  const toggleClass = (clazz: string) => {
    setSelectedClasses((prev) => {
      const next = new Set(prev);
      if (next.has(clazz)) {
        next.delete(clazz);
      } else {
        next.add(clazz);
      }
      return next;
    });
  };

  const toggleProt = (prot: string) => {
    setSelectedProts((prev) => {
      const next = new Set(prev);
      if (next.has(prot)) {
        next.delete(prot);
      } else {
        next.add(prot);
      }
      return next;
    });
  };

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      const clazz = item.clazz || "";
      const prot = item.prot || "";
      if (selectedClasses.size > 0 && !selectedClasses.has(clazz)) {
        return false;
      }
      if (selectedProts.size > 0 && !selectedProts.has(prot)) {
        return false;
      }
      return true;
    });
  }, [items, selectedClasses, selectedProts]);

  const clearFilters = () => {
    setSelectedClasses(new Set());
    setSelectedProts(new Set());
  };

  const columns: ColumnDef<KeyChainItem>[] = [
      {
        id: "expand",
        header: "",
        size: 32,
        minSize: 32,
        enableResizing: false,
        cell: ({ row }) =>
          row.getIsExpanded() ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          ),
      },
      {
        accessorKey: "service",
        header: () => (
          <>
            <Server className="w-4 h-4 inline mr-1" />
            {t("service")}
          </>
        ),
        size: 160,
        minSize: 80,
        cell: ({ row }) => (
          <span
            className="truncate block font-mono"
            title={row.original.service}
          >
            {row.original.service || "-"}
          </span>
        ),
      },
      {
        accessorKey: "account",
        header: () => (
          <>
            <User className="w-4 h-4 inline mr-1" />
            {t("account")}
          </>
        ),
        size: 160,
        minSize: 80,
        cell: ({ row }) => (
          <span
            className="truncate block font-mono"
            title={row.original.account}
          >
            {row.original.account || "-"}
          </span>
        ),
      },
      {
        accessorKey: "label",
        header: () => (
          <>
            <Key className="w-4 h-4 inline mr-1" />
            {t("label")}
          </>
        ),
        size: 160,
        minSize: 80,
        cell: ({ row }) => row.original.label || "-",
      },
      {
        accessorKey: "entitlementGroup",
        header: () => (
          <>
            <Server className="w-4 h-4 inline mr-1" />
            {t("entitlement_group")}
          </>
        ),
        size: 192,
        minSize: 80,
        cell: ({ row }) => (
          <span
            className="truncate block"
            title={row.original.entitlementGroup}
          >
            {row.original.entitlementGroup || "-"}
          </span>
        ),
      },
      {
        accessorKey: "prot",
        header: () => (
          <Popover open={protFilterOpen} onOpenChange={setProtFilterOpen}>
            <PopoverTrigger
              render={<Button variant="ghost" size="sm" className="h-8 px-1" />}
            >
              <Server className="w-4 h-4 inline mr-1" />
              {t("prot")}
              {selectedProts.size > 0 && (
                <span className="ml-1 text-xs bg-primary text-primary-foreground rounded-full px-1.5">
                  {selectedProts.size}
                </span>
              )}
            </PopoverTrigger>
            <PopoverContent className="w-100 p-3" align="start">
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{t("filter")}</span>
                  {(selectedProts.size > 0 || allProts.length > 0) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={clearFilters}
                    >
                      {t("clear")}
                    </Button>
                  )}
                </div>
                <div className="max-h-48 overflow-y-auto flex flex-col gap-1">
                  {allProts.map((prot) => (
                    <label
                      key={prot}
                      className="flex items-center gap-2 cursor-pointer hover:bg-accent px-1 rounded"
                    >
                      <Checkbox
                        checked={selectedProts.has(prot)}
                        onCheckedChange={() => toggleProt(prot)}
                      />
                      <span className="text-sm truncate">{prot}</span>
                    </label>
                  ))}
                  {allProts.length === 0 && (
                    <span className="text-sm text-muted-foreground">
                      {t("no_values")}
                    </span>
                  )}
                </div>
              </div>
            </PopoverContent>
          </Popover>
        ),
        size: 128,
        minSize: 60,
        cell: ({ row }) => (
          <span className="truncate block" title={row.original.prot}>
            {row.original.prot || "-"}
          </span>
        ),
      },
      {
        accessorKey: "clazz",
        header: () => (
          <Popover open={classFilterOpen} onOpenChange={setClassFilterOpen}>
            <PopoverTrigger
              render={<Button variant="ghost" size="sm" className="h-8 px-1" />}
            >
              {t("class")}
              {selectedClasses.size > 0 && (
                <span className="ml-1 text-xs bg-primary text-primary-foreground rounded-full px-1.5">
                  {selectedClasses.size}
                </span>
              )}
            </PopoverTrigger>
            <PopoverContent className="w-48 p-3" align="start">
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{t("filter")}</span>
                  {(selectedClasses.size > 0 || allClasses.length > 0) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={clearFilters}
                    >
                      {t("clear")}
                    </Button>
                  )}
                </div>
                <div className="max-h-48 overflow-y-auto flex flex-col gap-1">
                  {allClasses.map((clazz) => (
                    <label
                      key={clazz}
                      className="flex items-center gap-2 cursor-pointer hover:bg-accent px-1 rounded"
                    >
                      <Checkbox
                        checked={selectedClasses.has(clazz)}
                        onCheckedChange={() => toggleClass(clazz)}
                      />
                      <span className="text-sm">{clazz}</span>
                    </label>
                  ))}
                  {allClasses.length === 0 && (
                    <span className="text-sm text-muted-foreground">
                      {t("no_values")}
                    </span>
                  )}
                </div>
              </div>
            </PopoverContent>
          </Popover>
        ),
        size: 96,
        minSize: 60,
        cell: ({ row }) => row.original.clazz || "-",
      },
      {
        accessorKey: "acl",
        header: () => t("acl"),
        size: 192,
        minSize: 80,
        cell: ({ row }) => (
          <span className="truncate block" title={row.original.acl}>
            {row.original.acl || "-"}
          </span>
        ),
      },
      {
        id: "actions",
        header: () => t("actions"),
        size: 96,
        minSize: 60,
        enableResizing: false,
        cell: ({ row }) => {
          const item = row.original;
          return (
            <div
              className="flex justify-end gap-1"
              onClick={(e) => e.stopPropagation()}
            >
              <DropdownMenu>
                <DropdownMenuTrigger
                  render={
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      title={t("remove")}
                    />
                  }
                >
                  <Trash2 className="h-4 w-4" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem
                    onClick={() => handleDelete(item)}
                    className="text-destructive focus:text-destructive"
                  >
                    {t("remove")}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          );
        },
      },
  ];

  const table = useReactTable({
    data: filteredItems,
    columns,
    state: { columnSizing, expanded },
    onColumnSizingChange: setColumnSizing,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    columnResizeMode: "onChange" as ColumnResizeMode,
    enableColumnResizing: true,
  });

  const expandAll = () => {
    const allExpanded: Record<string, boolean> = {};
    filteredItems.forEach((_, i) => {
      allExpanded[String(i)] = true;
    });
    setExpanded(allExpanded);
  };

  const collapseAll = () => {
    setExpanded({});
  };

  const hasExpanded =
    typeof expanded === "object" && Object.keys(expanded).length > 0;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 p-2 border-b">
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          disabled={isLoading}
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          {t("reload")}
        </Button>
        <div className="flex">
          <Button
            variant="outline"
            size="sm"
            className="rounded-r-none border-r-0"
            onClick={expandAll}
            disabled={isLoading || filteredItems.length === 0}
            title={t("expand_all")}
          >
            <ChevronsUpDown className="w-4 h-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="rounded-l-none"
            onClick={collapseAll}
            disabled={isLoading || !hasExpanded}
            title={t("collapse_all")}
          >
            <ChevronsDownUp className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex items-center gap-2 ml-auto">
          <label className="text-sm flex items-center gap-2">
            <input
              type="checkbox"
              checked={withBiometricId}
              onChange={(e) => setWithBiometricId(e.target.checked)}
              className="rounded"
            />
            {t("require_biometric_id")}
          </label>
        </div>
      </div>
      <div className="flex-1 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_keychain_items")}
          </div>
        ) : (
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
              {table.getRowModel().rows.map((row) => (
                <>
                  <tr
                    key={row.id}
                    className="border-b hover:bg-muted/50 cursor-pointer"
                    onClick={() => row.toggleExpanded()}
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
                  {row.getIsExpanded() && (
                    <tr key={`${row.id}-detail`} className="border-b">
                      <td
                        colSpan={columns.length}
                        className="bg-muted/50 px-4 py-3"
                      >
                        <div className="space-y-2 text-xs">
                          <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                            <div className="flex gap-2">
                              <span className="text-muted-foreground shrink-0">
                                {t("creation_time")}:
                              </span>
                              <span className="font-mono truncate">
                                {row.original.creation
                                  ? new Date(
                                      row.original.creation,
                                    ).toLocaleString()
                                  : "-"}
                              </span>
                            </div>
                            <div className="flex gap-2">
                              <span className="text-muted-foreground shrink-0">
                                {t("modification_time")}:
                              </span>
                              <span className="font-mono truncate">
                                {row.original.modification
                                  ? new Date(
                                      row.original.modification,
                                    ).toLocaleString()
                                  : "-"}
                              </span>
                            </div>
                            <div className="flex gap-2">
                              <span className="text-muted-foreground shrink-0">
                                {t("comment")}:
                              </span>
                              <span
                                className="font-mono truncate"
                                title={row.original.comment}
                              >
                                {row.original.comment || "-"}
                              </span>
                            </div>
                            <div className="flex gap-2">
                              <span className="text-muted-foreground shrink-0">
                                {t("creator")}:
                              </span>
                              <span
                                className="font-mono truncate"
                                title={row.original.creator}
                              >
                                {row.original.creator || "-"}
                              </span>
                            </div>
                          </div>
                          <div className="flex gap-4 text-muted-foreground">
                            <span>
                              {t("alias")}:{" "}
                              <span className="text-foreground">
                                {formatBoolean(row.original.alias)}
                              </span>
                            </span>
                            <span>
                              {t("invisible")}:{" "}
                              <span className="text-foreground">
                                {formatBoolean(row.original.invisible)}
                              </span>
                            </span>
                            <span>
                              {t("custom_icon")}:{" "}
                              <span className="text-foreground">
                                {formatBoolean(row.original.customIcon)}
                              </span>
                            </span>
                          </div>
                          {row.original.data && (
                            <div className="flex gap-2">
                              <span className="text-muted-foreground shrink-0">
                                {t("data")}:
                              </span>
                              <span
                                className="font-mono truncate"
                                title={row.original.data}
                              >
                                {row.original.data}
                              </span>
                            </div>
                          )}
                          {row.original.raw && (
                            <div>
                              <div className="flex items-center gap-1 mb-1">
                                <span className="text-muted-foreground">
                                  {t("raw")}:
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-5 w-5"
                                  onClick={() => downloadRaw(row.original)}
                                  title={t("download")}
                                >
                                  <Download className="h-3 w-3" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-5 w-5"
                                  onClick={() =>
                                    copyToClipboardRaw(row.original, row.id)
                                  }
                                  title={t("copy")}
                                >
                                  {copySuccessIndex === row.id ? (
                                    <Check className="h-3 w-3 text-green-500" />
                                  ) : (
                                    <Copy className="h-3 w-3" />
                                  )}
                                </Button>
                              </div>
                              <pre className="font-mono text-xs bg-background/50 p-2 rounded overflow-x-auto max-h-40">
                                {hexDump(row.original.raw)}
                              </pre>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
