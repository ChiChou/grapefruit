import { useState } from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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

import type { KeyChainItem } from "../../../../agent/types/fruity/modules/keychain";

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

export function KeyChainTab() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [withBiometricId, setWithBiometricId] = useState(false);
  const [expandedIndices, setExpandedIndices] = useState<Set<number>>(new Set());
  const [copySuccessIndex, setCopySuccessIndex] = useState<number | null>(null);
  const [classFilterOpen, setClassFilterOpen] = useState(false);
  const [protFilterOpen, setProtFilterOpen] = useState(false);
  const [selectedClasses, setSelectedClasses] = useState<Set<string>>(
    new Set(),
  );
  const [selectedProts, setSelectedProts] = useState<Set<string>>(new Set());

  const {
    data: items = [],
    isLoading,
    refetch,
  } = useRpcQuery<KeyChainItem[]>(
    ["keychain", String(withBiometricId)],
    (api) => api.keychain.list(withBiometricId)
  );

  const removeMutation = useRpcMutation<void, { service: string; account: string }>(
    (api, { service, account }) => api.keychain.remove(service, account),
    {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["keychain"] });
      },
    }
  );

  const handleDelete = async (item: KeyChainItem) => {
    const service = item.service || "";
    const account = item.account || "";
    await removeMutation.mutateAsync({ service, account });
  };

  const toggleExpand = (index: number) => {
    setExpandedIndices((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
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

  const copyToClipboardRaw = async (item: KeyChainItem, index: number) => {
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
      setCopySuccessIndex(index);
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

  const filteredItems = items.filter((item) => {
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

  const clearFilters = () => {
    setSelectedClasses(new Set());
    setSelectedProts(new Set());
  };

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
          <div className="flex items-center justify-center h-full gap-2 text-gray-500">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("no_keychain_items")}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead className="w-40">
                  <Server className="w-4 h-4 inline mr-1" />
                  {t("service")}
                </TableHead>
                <TableHead className="w-40">
                  <User className="w-4 h-4 inline mr-1" />
                  {t("account")}
                </TableHead>
                <TableHead className="w-40">
                  <Key className="w-4 h-4 inline mr-1" />
                  {t("label")}
                </TableHead>
                <TableHead className="w-48">
                  <Server className="w-4 h-4 inline mr-1" />
                  {t("entitlement_group")}
                </TableHead>
                <TableHead className="w-32">
                  <Popover
                    open={protFilterOpen}
                    onOpenChange={setProtFilterOpen}
                  >
                    <PopoverTrigger asChild>
                      <Button variant="ghost" size="sm" className="h-8 px-1">
                        <Server className="w-4 h-4 inline mr-1" />
                        {t("prot")}
                        {selectedProts.size > 0 && (
                          <span className="ml-1 text-xs bg-primary text-primary-foreground rounded-full px-1.5">
                            {selectedProts.size}
                          </span>
                        )}
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent className="w-100 p-3" align="start">
                      <div className="flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-sm">
                            {t("filter")}
                          </span>
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
                </TableHead>
                <TableHead className="w-24">
                  <Popover
                    open={classFilterOpen}
                    onOpenChange={setClassFilterOpen}
                  >
                    <PopoverTrigger asChild>
                      <Button variant="ghost" size="sm" className="h-8 px-1">
                        {t("class")}
                        {selectedClasses.size > 0 && (
                          <span className="ml-1 text-xs bg-primary text-primary-foreground rounded-full px-1.5">
                            {selectedClasses.size}
                          </span>
                        )}
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent className="w-48 p-3" align="start">
                      <div className="flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-sm">
                            {t("filter")}
                          </span>
                          {(selectedClasses.size > 0 ||
                            allClasses.length > 0) && (
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
                </TableHead>
                <TableHead className="w-48">{t("acl")}</TableHead>
                <TableHead className="w-24 text-right">
                  {t("actions")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredItems.map((item, index) => (
                <>
                  <TableRow
                    key={`row-${index}`}
                    className="cursor-pointer"
                    onClick={() => toggleExpand(index)}
                  >
                    <TableCell>
                      {expandedIndices.has(index) ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </TableCell>
                    <TableCell
                      className="font-mono text-sm truncate max-w-[150px]"
                      title={item.service}
                    >
                      {item.service || "-"}
                    </TableCell>
                    <TableCell
                      className="font-mono text-sm truncate max-w-[150px]"
                      title={item.account}
                    >
                      {item.account || "-"}
                    </TableCell>
                    <TableCell className="font-mono text-sm truncate max-w-[150px]">
                      {item.label || "-"}
                    </TableCell>
                    <TableCell
                      className="font-mono text-sm truncate max-w-[180px]"
                      title={item.entitlementGroup}
                    >
                      {item.entitlementGroup || "-"}
                    </TableCell>
                    <TableCell
                      className="font-mono text-sm truncate max-w-[120px]"
                      title={item.prot}
                    >
                      {item.prot || "-"}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {item.clazz || "-"}
                    </TableCell>
                    <TableCell
                      className="font-mono text-sm truncate max-w-[180px]"
                      title={item.acl}
                    >
                      {item.acl || "-"}
                    </TableCell>
                    <TableCell
                      className="text-right"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex justify-end gap-1">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-destructive hover:text-destructive"
                              title={t("remove")}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
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
                    </TableCell>
                  </TableRow>
                  {expandedIndices.has(index) && (
                    <TableRow key={`detail-${index}`}>
                      <TableCell
                        colSpan={9}
                        className="bg-gray-50 dark:bg-gray-900 p-4"
                      >
                        <div className="grid grid-cols-4 gap-4 text-sm">
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("creation_time")}:
                            </span>
                            <div className="font-mono">
                              {item.creation
                                ? new Date(item.creation).toLocaleString()
                                : "-"}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("modification_time")}:
                            </span>
                            <div className="font-mono">
                              {item.modification
                                ? new Date(item.modification).toLocaleString()
                                : "-"}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("comment")}:
                            </span>
                            <div
                              className="font-mono truncate"
                              title={item.comment}
                            >
                              {item.comment || "-"}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("creator")}:
                            </span>
                            <div
                              className="font-mono truncate"
                              title={item.creator}
                            >
                              {item.creator || "-"}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("alias")}:
                            </span>
                            <div>{formatBoolean(item.alias)}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("invisible")}:
                            </span>
                            <div>{formatBoolean(item.invisible)}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">
                              {t("custom_icon")}:
                            </span>
                            <div>{formatBoolean(item.customIcon)}</div>
                          </div>
                          <div className="col-span-2">
                            <span className="font-medium text-gray-500">
                              {t("data")}:
                            </span>
                            <div
                              className="font-mono text-xs truncate max-w-[400px]"
                              title={item.data}
                            >
                              {item.data || "-"}
                            </div>
                          </div>
                          <div className="col-span-4">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-gray-500">
                                {t("raw")}:
                              </span>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6"
                                onClick={() => downloadRaw(item)}
                                disabled={!item.raw}
                                title={t("download")}
                              >
                                <Download className="h-3 w-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6"
                                onClick={() => copyToClipboardRaw(item, index)}
                                disabled={!item.raw}
                                title={t("copy")}
                              >
                                {copySuccessIndex === index ? (
                                  <Check className="h-3 w-3 text-green-500" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                              </Button>
                            </div>
                            <pre className="font-mono text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded mt-1 overflow-x-auto">
                              {hexDump(item.raw)}
                            </pre>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
