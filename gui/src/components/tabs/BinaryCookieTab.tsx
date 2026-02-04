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
import { Input } from "@/components/ui/input";
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
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Calendar as CalendarComponent } from "@/components/ui/calendar";
import { useSession } from "@/context/SessionContext";
import { useRpcQuery, useRpcMutation, useQueryClient } from "@/lib/queries";
import type {
  Cookie,
  CookiePredicate,
} from "../../../../agent/types/fruity/modules/cookies";

function formatDate(date: Date | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleString();
}

export function BinaryCookieTab() {
  const { t } = useTranslation();
  const { fruity } = useSession();
  const queryClient = useQueryClient();
  const [pendingDeleteCookie, setPendingDeleteCookie] = useState<Cookie | null>(
    null,
  );
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [dialogMessage, setDialogMessage] = useState<string | null>(null);
  const [isClearMode, setIsClearMode] = useState(false);

  const [editingCookie, setEditingCookie] = useState<Cookie | null>(null);
  const [editValue, setEditValue] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [editingExpiresCookie, setEditingExpiresCookie] =
    useState<Cookie | null>(null);
  const [expiresDate, setExpiresDate] = useState<Date>(new Date());
  const [isExpiresPopoverOpen, setIsExpiresPopoverOpen] = useState(false);

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
    }
  );

  const removeMutation = useRpcMutation<boolean, CookiePredicate>(
    (api, predicate) => api.cookies.remove(predicate),
    {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["cookies"] });
      },
    }
  );

  const confirmClear = async () => {
    await clearMutation.mutateAsync();
    setPendingDeleteCookie(null);
    setIsDialogOpen(false);
    setIsClearMode(false);
    setDialogMessage(null);
  };

  const requestClear = () => {
    setDialogMessage(t("clear_all_cookies_confirmation"));
    setIsClearMode(true);
    setIsDialogOpen(true);
  };

  const handleRemove = async (cookie: Cookie) => {
    await removeMutation.mutateAsync({
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
    } as CookiePredicate);
  };

  const requestDelete = (cookie: Cookie) => {
    setPendingDeleteCookie(cookie);
    setIsClearMode(false);
    setDialogMessage(null);
    setIsDialogOpen(true);
  };

  const confirmDelete = async () => {
    if (pendingDeleteCookie) {
      await handleRemove(pendingDeleteCookie);
      setPendingDeleteCookie(null);
      setIsDialogOpen(false);
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
      const success = await fruity.cookies.update(predicate, "value", editValue);
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
        <Button
          variant="destructive"
          size="sm"
          onClick={requestClear}
          disabled={isLoading || cookies.length === 0}
        >
          <Trash2 className="w-4 h-4 mr-2" />
          {t("clear")}
        </Button>
      </div>
      <div className="flex-1 overflow-auto">
        {isLoading && cookies.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("loading")}...
          </div>
        ) : cookies.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("no_cookies")}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-48">
                  <Globe className="w-4 h-4 inline mr-1" />
                  {t("domain")}
                </TableHead>
                <TableHead className="w-40">
                  <Shield className="w-4 h-4 inline mr-1" />
                  {t("name")}
                </TableHead>
                <TableHead>{t("value")}</TableHead>
                <TableHead className="w-32">
                  <Calendar className="w-4 h-4 inline mr-1" />
                  {t("expires")}
                </TableHead>
                <TableHead className="w-24">{t("path")}</TableHead>
                <TableHead className="w-20 text-center">
                  <Lock className="w-4 h-4 inline mr-1" />
                  {t("secure")}
                </TableHead>
                <TableHead className="w-20 text-center">
                  HTTP Only {/* no need to translate*/}
                </TableHead>
                <TableHead className="w-20 text-center">
                  Session Cookie
                </TableHead>
                <TableHead className="w-24 text-right"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {cookies.map((cookie) => (
                <TableRow key={`${cookie.domain}${cookie.path}${cookie.name}`}>
                  <TableCell
                    className="font-mono text-sm truncate max-w-[180px]"
                    title={cookie.domain}
                  >
                    {cookie.domain}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {cookie.name}
                  </TableCell>
                  <TableCell className="font-mono text-sm max-w-[200px]">
                    {editingCookie?.name === cookie.name &&
                    editingCookie?.domain === cookie.domain &&
                    editingCookie?.path === cookie.path ? (
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
                    ) : (
                      <button
                        type="button"
                        className="w-full text-left hover:bg-gray-100 dark:hover:bg-gray-800 px-1 py-0.5 rounded truncate"
                        onClick={() => startEditing(cookie)}
                        title={cookie.value}
                      >
                        {cookie.value}
                      </button>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">
                    <Popover
                      open={
                        isExpiresPopoverOpen &&
                        editingExpiresCookie?.name === cookie.name &&
                        editingExpiresCookie?.domain === cookie.domain &&
                        editingExpiresCookie?.path === cookie.path
                      }
                      onOpenChange={(open) => {
                        if (open) {
                          startEditingExpires(cookie);
                        } else {
                          cancelEditingExpires();
                        }
                      }}
                    >
                      <PopoverTrigger asChild>
                        <button
                          type="button"
                          className="w-full text-left hover:bg-gray-100 dark:hover:bg-gray-800 px-1 py-0.5 rounded"
                        >
                          {formatDate(cookie.expiresDate)}
                        </button>
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
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {cookie.path}
                  </TableCell>
                  <TableCell className="text-center">
                    {cookie.isSecure ? (
                      <span className="text-green-600">✓</span>
                    ) : (
                      <span className="text-gray-300">-</span>
                    )}
                  </TableCell>
                  <TableCell className="text-center">
                    {cookie.isHTTPOnly ? (
                      <span className="text-green-600">✓</span>
                    ) : (
                      <span className="text-gray-300">-</span>
                    )}
                  </TableCell>
                  <TableCell className="text-center">
                    {cookie.isSessionOnly ? (
                      <span className="text-blue-600">✓</span>
                    ) : (
                      <span className="text-gray-300">-</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-destructive hover:text-destructive"
                        onClick={() => requestDelete(cookie)}
                        title={t("remove")}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
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
              {isClearMode && dialogMessage
                ? dialogMessage
                : t("delete_cookie_confirmation", {
                    name: pendingDeleteCookie?.name,
                  })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              {t("cancel")}
            </Button>
            <Button
              variant="destructive"
              onClick={isClearMode ? confirmClear : confirmDelete}
            >
              {t("delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
