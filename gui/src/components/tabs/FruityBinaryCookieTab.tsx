import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  RefreshCw,
  Trash2,
  Shield,
  Globe,
  Calendar,
  Lock,
  Check,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { Input } from "@/components/ui/input";
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
import { Calendar as CalendarComponent } from "@/components/ui/calendar";
import { toast } from "sonner";
import { useSession } from "@/context/SessionContext";
import { useRpcQuery, useRpcMutation, useQueryClient } from "@/lib/queries";
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
  type ColumnResizeMode,
} from "@tanstack/react-table";
import type { Cookie, CookiePredicate } from "@agent/fruity/modules/cookies";

function formatDate(date: Date | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleString();
}

export function FruityBinaryCookieTab() {
  const { t } = useTranslation();
  const { fruity } = useSession();
  const queryClient = useQueryClient();

  const [editingCookie, setEditingCookie] = useState<Cookie | null>(null);
  const [editValue, setEditValue] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [editingExpiresCookie, setEditingExpiresCookie] =
    useState<Cookie | null>(null);
  const [expiresDate, setExpiresDate] = useState<Date>(new Date());
  const [isExpiresPopoverOpen, setIsExpiresPopoverOpen] = useState(false);
  const [columnSizing, setColumnSizing] = useState<Record<string, number>>({});

  const {
    data: cookies = [],
    isLoading,
    refetch,
  } = useRpcQuery<Cookie[]>(["cookies"], (api) => api.cookies.list());

  const clearMutation = useRpcMutation<void, void>(
    (api) => api.cookies.clear(),
    {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["cookies"] });
      },
    },
  );

  const removeMutation = useRpcMutation<boolean, CookiePredicate>(
    (api, predicate) => api.cookies.remove(predicate),
    {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["cookies"] });
      },
    },
  );

  const handleClear = async () => {
    try {
      await clearMutation.mutateAsync();
      toast.success(t("cookies_cleared"));
      refetch();
    } catch (err) {
      console.error("Failed to clear cookies:", err);
      toast.error(t("failed_to_clear_cookies"));
    }
  };

  const handleRemove = async (cookie: Cookie) => {
    try {
      await removeMutation.mutateAsync({
        name: cookie.name,
        domain: cookie.domain,
        path: cookie.path,
      } as CookiePredicate);
      toast.success(t("cookie_removed"));
    } catch (err) {
      console.error("Failed to remove cookie:", err);
      toast.error(t("failed_to_remove_cookie"));
    }
  };

  const startEditing = (cookie: Cookie) => {
    setEditingCookie(cookie);
    setEditValue(cookie.value);
  };

  const cancelEditing = () => {
    setEditingCookie(null);
    setEditValue("");
  };

  const saveValue = async () => {
    if (!fruity || !editingCookie) return;
    setIsSaving(true);
    try {
      const predicate: CookiePredicate = {
        name: editingCookie.name,
        domain: editingCookie.domain,
        path: editingCookie.path,
      };
      const success = await fruity.cookies.update(
        predicate,
        "value",
        editValue,
      );
      if (success) {
        queryClient.invalidateQueries({ queryKey: ["cookies"] });
        setEditingCookie(null);
        setEditValue("");
      }
    } finally {
      setIsSaving(false);
    }
  };

  const startEditingExpires = (cookie: Cookie) => {
    setEditingExpiresCookie(cookie);
    setExpiresDate(
      cookie.expiresDate ? new Date(cookie.expiresDate) : new Date(),
    );
    setIsExpiresPopoverOpen(true);
  };

  const cancelEditingExpires = () => {
    setEditingExpiresCookie(null);
    setIsExpiresPopoverOpen(false);
  };

  const saveExpiresDate = async () => {
    if (!fruity || !editingExpiresCookie) return;
    setIsSaving(true);
    try {
      const predicate: CookiePredicate = {
        name: editingExpiresCookie.name,
        domain: editingExpiresCookie.domain,
        path: editingExpiresCookie.path,
      };
      const success = await fruity.cookies.update(
        predicate,
        "expiresDate",
        expiresDate.getTime(),
      );
      if (success) {
        queryClient.invalidateQueries({ queryKey: ["cookies"] });
        setEditingExpiresCookie(null);
        setIsExpiresPopoverOpen(false);
      }
    } finally {
      setIsSaving(false);
    }
  };

  const columns: ColumnDef<Cookie>[] = [
      {
        accessorKey: "domain",
        header: () => (
          <>
            <Globe className="w-4 h-4 inline mr-1" />
            {t("domain")}
          </>
        ),
        size: 192,
        minSize: 100,
        cell: ({ row }) => (
          <span className="truncate block" title={row.original.domain}>
            {row.original.domain}
          </span>
        ),
      },
      {
        accessorKey: "name",
        header: () => (
          <>
            <Shield className="w-4 h-4 inline mr-1" />
            {t("name")}
          </>
        ),
        size: 160,
        minSize: 80,
      },
      {
        accessorKey: "value",
        header: () => t("value"),
        size: 200,
        minSize: 120,
        cell: ({ row }) => {
          const cookie = row.original;
          const isEditing =
            editingCookie?.name === cookie.name &&
            editingCookie?.domain === cookie.domain &&
            editingCookie?.path === cookie.path;

          if (isEditing) {
            return (
              <div className="flex items-center gap-1">
                <Input
                  value={editValue}
                  onChange={(e) => setEditValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      saveValue();
                    } else if (e.key === "Escape") {
                      e.preventDefault();
                      cancelEditing();
                    }
                  }}
                  className="h-7 text-xs"
                  disabled={isSaving}
                  autoFocus
                />
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-green-600"
                  onClick={saveValue}
                  disabled={isSaving}
                  title={t("save")}
                >
                  <Check className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={cancelEditing}
                  disabled={isSaving}
                  title={t("discard")}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            );
          }

          return (
            <button
              type="button"
              className="w-full text-left hover:bg-accent px-1 py-0.5 rounded truncate"
              onClick={() => startEditing(cookie)}
              title={cookie.value}
            >
              {cookie.value}
            </button>
          );
        },
      },
      {
        accessorKey: "expiresDate",
        header: () => (
          <>
            <Calendar className="w-4 h-4 inline mr-1" />
            {t("expires")}
          </>
        ),
        size: 128,
        minSize: 80,
        cell: ({ row }) => {
          const cookie = row.original;
          const isEditingExpires =
            isExpiresPopoverOpen &&
            editingExpiresCookie?.name === cookie.name &&
            editingExpiresCookie?.domain === cookie.domain &&
            editingExpiresCookie?.path === cookie.path;

          return (
            <Popover
              open={isEditingExpires}
              onOpenChange={(open) => {
                if (open) {
                  startEditingExpires(cookie);
                } else {
                  cancelEditingExpires();
                }
              }}
            >
              <PopoverTrigger
                render={
                  <button
                    type="button"
                    className="w-full text-left hover:bg-accent px-1 py-0.5 rounded"
                  />
                }
              >
                {formatDate(cookie.expiresDate)}
              </PopoverTrigger>
              <PopoverContent className="w-auto p-3" align="start">
                <div className="flex flex-col gap-3">
                  <CalendarComponent
                    mode="single"
                    selected={expiresDate}
                    onSelect={(date) => date && setExpiresDate(date)}
                    className="rounded-md border"
                  />
                  <div className="flex items-center gap-2">
                    <Input
                      type="time"
                      value={expiresDate.toTimeString().slice(0, 5)}
                      onChange={(e) => {
                        const [hours, minutes] = e.target.value
                          .split(":")
                          .map(Number);
                        const newDate = new Date(expiresDate);
                        newDate.setHours(hours, minutes);
                        setExpiresDate(newDate);
                      }}
                      className="w-24"
                    />
                  </div>
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={cancelEditingExpires}
                    >
                      Discard
                    </Button>
                    <Button
                      size="sm"
                      onClick={saveExpiresDate}
                      disabled={isSaving}
                    >
                      Save
                    </Button>
                  </div>
                </div>
              </PopoverContent>
            </Popover>
          );
        },
      },
      {
        accessorKey: "path",
        header: () => t("path"),
        size: 96,
        minSize: 60,
      },
      {
        accessorKey: "isSecure",
        header: () => (
          <span className="flex items-center justify-center">
            <Lock className="w-4 h-4 inline mr-1" />
            {t("secure")}
          </span>
        ),
        size: 80,
        minSize: 50,
        cell: ({ row }) =>
          row.original.isSecure ? (
            <span className="text-green-600 text-center block">✓</span>
          ) : (
            <span className="text-muted-foreground text-center block">-</span>
          ),
      },
      {
        accessorKey: "isHTTPOnly",
        header: () => (
          <span className="flex items-center justify-center">HTTP Only</span>
        ),
        size: 80,
        minSize: 50,
        cell: ({ row }) =>
          row.original.isHTTPOnly ? (
            <span className="text-green-600 text-center block">✓</span>
          ) : (
            <span className="text-muted-foreground text-center block">-</span>
          ),
      },
      {
        accessorKey: "isSessionOnly",
        header: () => (
          <span className="flex items-center justify-center">
            Session Cookie
          </span>
        ),
        size: 80,
        minSize: 50,
        cell: ({ row }) =>
          row.original.isSessionOnly ? (
            <span className="text-amber-600 text-center block">✓</span>
          ) : (
            <span className="text-muted-foreground text-center block">-</span>
          ),
      },
      {
        id: "actions",
        header: "",
        size: 96,
        minSize: 60,
        enableResizing: false,
        cell: ({ row }) => {
          const cookie = row.original;
          return (
            <div className="flex justify-end gap-1">
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
                    onClick={() => handleRemove(cookie)}
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
    data: cookies,
    columns,
    state: { columnSizing },
    onColumnSizingChange: setColumnSizing,
    getCoreRowModel: getCoreRowModel(),
    columnResizeMode: "onChange" as ColumnResizeMode,
    enableColumnResizing: true,
  });

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
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                variant="destructive"
                size="sm"
                disabled={isLoading || cookies.length === 0}
              />
            }
          >
            <Trash2 className="w-4 h-4 mr-2" />
            {t("clear")}
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem
              onClick={handleClear}
              className="text-destructive focus:text-destructive"
            >
              {t("clear")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <div className="flex-1 overflow-auto">
        {isLoading && cookies.length === 0 ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
            {t("loading")}...
          </div>
        ) : cookies.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_cookies")}
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
                <tr
                  key={`${row.original.domain}${row.original.path}${row.original.name}`}
                  className="border-b hover:bg-muted/50"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="p-2 font-mono text-xs"
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
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
