import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { RotateCcw, Trash2, Key, User, Server, ChevronDown, ChevronRight, Download, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Status, useSession } from "@/context/SessionContext";

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
  const { api, status } = useSession();
  const [items, setItems] = useState<KeyChainItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [withBiometricId, setWithBiometricId] = useState(false);
  const [pendingDeleteItem, setPendingDeleteItem] =
    useState<KeyChainItem | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const [copySuccessIndex, setCopySuccessIndex] = useState<number | null>(null);

  const loadItems = useCallback(async () => {
    if (!api) return;
    setIsLoading(true);
    try {
      const list = await api.keychain.list(withBiometricId);
      setItems(list);
    } catch {
      setItems([]);
    } finally {
      setIsLoading(false);
    }
  }, [api, withBiometricId]);

  useEffect(() => {
    if (api && status === Status.Ready) {
      loadItems();
    }
  }, [api, status, loadItems]);

  const requestDelete = (item: KeyChainItem) => {
    setPendingDeleteItem(item);
    setIsDialogOpen(true);
  };

  const confirmDelete = async () => {
    if (!api || !pendingDeleteItem) return;
    const service = pendingDeleteItem.service || "";
    const account = pendingDeleteItem.account || "";
    await api.keychain.remove(service, account);
    setItems((prev) =>
      prev.filter((i) => !(i.service === service && i.account === account)),
    );
    setPendingDeleteItem(null);
    setIsDialogOpen(false);
  };

  const toggleExpand = (index: number) => {
    setExpandedIndex(expandedIndex === index ? null : index);
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

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 p-2 border-b">
        <Button
          variant="outline"
          size="sm"
          onClick={loadItems}
          disabled={isLoading}
        >
          <RotateCcw className="w-4 h-4 mr-2" />
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
        {isLoading && items.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("loading")}...
          </div>
        ) : items.length === 0 ? (
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
                  <Server className="w-4 h-4 inline mr-1" />
                  {t("prot")}
                </TableHead>
                <TableHead className="w-24">{t("class")}</TableHead>
                <TableHead className="w-48">{t("acl")}</TableHead>
                <TableHead className="w-24 text-right">
                  {t("actions")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item, index) => (
                <>
                  <TableRow key={`row-${index}`} className="cursor-pointer" onClick={() => toggleExpand(index)}>
                    <TableCell>
                      {expandedIndex === index ? (
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
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive hover:text-destructive"
                          onClick={() => requestDelete(item)}
                          title={t("remove")}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                  {expandedIndex === index && (
                    <TableRow key={`detail-${index}`}>
                      <TableCell colSpan={9} className="bg-gray-50 dark:bg-gray-900 p-4">
                        <div className="grid grid-cols-4 gap-4 text-sm">
                          <div>
                            <span className="font-medium text-gray-500">{t("creation_time")}:</span>
                            <div className="font-mono">{item.creation ? new Date(item.creation).toLocaleString() : "-"}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">{t("modification_time")}:</span>
                            <div className="font-mono">{item.modification ? new Date(item.modification).toLocaleString() : "-"}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">{t("comment")}:</span>
                            <div className="font-mono truncate" title={item.comment}>
                              {item.comment || "-"}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">{t("creator")}:</span>
                            <div className="font-mono truncate" title={item.creator}>
                              {item.creator || "-"}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">{t("alias")}:</span>
                            <div>{formatBoolean(item.alias)}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">{t("invisible")}:</span>
                            <div>{formatBoolean(item.invisible)}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-500">{t("custom_icon")}:</span>
                            <div>{formatBoolean(item.customIcon)}</div>
                          </div>
                          <div className="col-span-2">
                            <span className="font-medium text-gray-500">{t("data")}:</span>
                            <div className="font-mono text-xs truncate max-w-[400px]" title={item.data}>
                              {item.data || "-"}
                            </div>
                          </div>
                          <div className="col-span-4">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-gray-500">{t("raw")}:</span>
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
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("confirmation")}</DialogTitle>
            <DialogDescription>
              {t("delete_keychain_confirmation", {
                service: pendingDeleteItem?.service,
                account: pendingDeleteItem?.account,
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              {t("cancel")}
            </Button>
            <Button variant="destructive" onClick={confirmDelete}>
              {t("delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
