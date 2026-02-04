import { useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import {
  RefreshCw,
  Trash2,
  Search,
  Edit2,
  Check,
  X,
  CalendarIcon,
  Clock,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useRpcQuery, useRpcMutation, useQueryClient } from "@/lib/queries";

import type { UserDefaultsEntry } from "../../../../agent/types/fruity/modules/userdefaults";

interface UserDefaultsItem extends UserDefaultsEntry {
  key: string;
}

function getTypeBadgeColor(type: string): string {
  switch (type) {
    case "string":
      return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
    case "number":
      return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
    case "date":
      return "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200";
    case "data":
      return "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200";
    case "array":
      return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
    case "dict":
      return "bg-pink-100 text-pink-800 dark:bg-pink-900 dark:text-pink-200";
    default:
      return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200";
  }
}

export function UserDefaultsTab() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [datePickerKey, setDatePickerKey] = useState<string | null>(null);
  const [datePickerValue, setDatePickerValue] = useState<Date | undefined>(
    undefined,
  );
  const [timeHours, setTimeHours] = useState<string>("00");
  const [timeMinutes, setTimeMinutes] = useState<string>("00");
  const [timeSeconds, setTimeSeconds] = useState<string>("00");

  const {
    data: defaults,
    isLoading,
    refetch,
  } = useRpcQuery(["userdefaults"], (api) => api.userdefaults.enumerate());

  const removeMutation = useRpcMutation(
    (api, { key }: { key: string }) => api.userdefaults.remove(key),
    {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["fruity", "userdefaults"] });
      },
    },
  );

  const updateMutation = useRpcMutation(
    (api, { key, value }: { key: string; value: string | number }) =>
      api.userdefaults.update(key, value),
    {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["fruity", "userdefaults"] });
        setEditingKey(null);
      },
    },
  );

  const items: UserDefaultsItem[] = useMemo(() => {
    if (!defaults) return [];
    return Object.entries(defaults).map(([key, entry]) => ({
      key,
      ...entry,
    }));
  }, [defaults]);

  const filteredItems = useMemo(() => {
    if (!searchQuery) return items;
    const query = searchQuery.toLowerCase();
    return items.filter(
      (item) =>
        item.key.toLowerCase().includes(query) ||
        item.readable.toLowerCase().includes(query),
    );
  }, [items, searchQuery]);

  const handleDelete = async (key: string) => {
    await removeMutation.mutateAsync({ key });
  };

  const startEdit = (item: UserDefaultsItem) => {
    if (item.type === "string") {
      setEditingKey(item.key);
      setEditValue(item.readable);
    }
  };

  const startDateEdit = (item: UserDefaultsItem) => {
    const date = new Date(item.readable);
    setDatePickerKey(item.key);
    setDatePickerValue(date);
    setTimeHours(date.getHours().toString().padStart(2, "0"));
    setTimeMinutes(date.getMinutes().toString().padStart(2, "0"));
    setTimeSeconds(date.getSeconds().toString().padStart(2, "0"));
  };

  const handleDateSelect = (date: Date | undefined) => {
    if (!date) return;
    // Keep the current time when selecting a new date
    const newDate = new Date(date);
    newDate.setHours(parseInt(timeHours) || 0);
    newDate.setMinutes(parseInt(timeMinutes) || 0);
    newDate.setSeconds(parseInt(timeSeconds) || 0);
    setDatePickerValue(newDate);
  };

  const saveDateTimeEdit = async () => {
    if (!datePickerValue || !datePickerKey) return;
    // Combine date with time
    const finalDate = new Date(datePickerValue);
    finalDate.setHours(parseInt(timeHours) || 0);
    finalDate.setMinutes(parseInt(timeMinutes) || 0);
    finalDate.setSeconds(parseInt(timeSeconds) || 0);
    // Convert to Unix timestamp (seconds)
    const timestamp = finalDate.getTime() / 1000;
    await updateMutation.mutateAsync({ key: datePickerKey, value: timestamp });
    setDatePickerKey(null);
    setDatePickerValue(undefined);
  };

  const closeDatePicker = () => {
    setDatePickerKey(null);
    setDatePickerValue(undefined);
  };

  const saveEdit = async (key: string) => {
    await updateMutation.mutateAsync({ key, value: editValue });
  };

  const cancelEdit = () => {
    setEditingKey(null);
    setEditValue("");
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
        <div className="flex-1 max-w-sm ml-auto">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder={t("search")}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 h-8"
            />
          </div>
        </div>
        <span className="text-sm text-muted-foreground">
          {filteredItems.length} / {items.length}
        </span>
      </div>
      <div className="flex-1 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-gray-500">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {searchQuery ? "No matching entries" : "No UserDefaults entries"}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-20">{t("type")}</TableHead>
                <TableHead className="min-w-[300px]">{t("key")}</TableHead>
                <TableHead>{t("value")}</TableHead>
                <TableHead className="w-24 text-right">
                  {t("actions")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredItems.map((item) => (
                <TableRow key={item.key}>
                  <TableCell>
                    <span
                      className={`px-2 py-1 text-xs rounded ${getTypeBadgeColor(item.type)}`}
                    >
                      {item.type}
                    </span>
                  </TableCell>
                  <TableCell
                    className="font-mono text-sm break-all"
                    title={item.key}
                  >
                    {item.key}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {editingKey === item.key ? (
                      <div className="flex items-center gap-2">
                        <Input
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          className="h-7 text-xs font-mono"
                        />
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          onClick={() => saveEdit(item.key)}
                          disabled={updateMutation.isPending}
                        >
                          <Check className="w-4 h-4 text-green-500" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          onClick={cancelEdit}
                        >
                          <X className="w-4 h-4 text-red-500" />
                        </Button>
                      </div>
                    ) : (
                      <pre
                        className="font-mono text-xs whitespace-pre-wrap break-all max-h-32 overflow-auto"
                        title={item.readable}
                      >
                        {item.readable}
                      </pre>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      {item.type === "string" && editingKey !== item.key && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={() => startEdit(item)}
                          title={t("edit")}
                        >
                          <Edit2 className="h-4 w-4" />
                        </Button>
                      )}
                      {item.type === "date" && (
                        <Popover
                          open={datePickerKey === item.key}
                          onOpenChange={(open) => {
                            if (!open) {
                              closeDatePicker();
                            }
                          }}
                        >
                          <PopoverTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => startDateEdit(item)}
                              title={t("edit")}
                            >
                              <CalendarIcon className="h-4 w-4" />
                            </Button>
                          </PopoverTrigger>
                          <PopoverContent className="w-auto p-3" align="end">
                            <Calendar
                              mode="single"
                              selected={datePickerValue}
                              onSelect={handleDateSelect}
                              defaultMonth={datePickerValue}
                            />
                            <div className="border-t pt-3 mt-3">
                              <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-muted-foreground" />
                                <Label className="text-sm">{t("time")}</Label>
                              </div>
                              <div className="flex items-center gap-1 mt-2">
                                <Input
                                  type="number"
                                  min="0"
                                  max="23"
                                  value={timeHours}
                                  onChange={(e) =>
                                    setTimeHours(
                                      e.target.value.padStart(2, "0").slice(-2),
                                    )
                                  }
                                  className="w-14 h-8 text-center font-mono"
                                  placeholder="HH"
                                />
                                <span className="text-lg">:</span>
                                <Input
                                  type="number"
                                  min="0"
                                  max="59"
                                  value={timeMinutes}
                                  onChange={(e) =>
                                    setTimeMinutes(
                                      e.target.value.padStart(2, "0").slice(-2),
                                    )
                                  }
                                  className="w-14 h-8 text-center font-mono"
                                  placeholder="MM"
                                />
                                <span className="text-lg">:</span>
                                <Input
                                  type="number"
                                  min="0"
                                  max="59"
                                  value={timeSeconds}
                                  onChange={(e) =>
                                    setTimeSeconds(
                                      e.target.value.padStart(2, "0").slice(-2),
                                    )
                                  }
                                  className="w-14 h-8 text-center font-mono"
                                  placeholder="SS"
                                />
                              </div>
                            </div>
                            <div className="flex justify-end gap-2 mt-3 pt-3 border-t">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={closeDatePicker}
                              >
                                {t("cancel")}
                              </Button>
                              <Button
                                size="sm"
                                onClick={saveDateTimeEdit}
                                disabled={updateMutation.isPending}
                              >
                                {t("save")}
                              </Button>
                            </div>
                          </PopoverContent>
                        </Popover>
                      )}
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
                            onClick={() => handleDelete(item.key)}
                            className="text-destructive focus:text-destructive"
                          >
                            {t("remove")}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
