import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Bookmark, Trash2, MapPin } from "lucide-react";
import { useR2 } from "@/context/R2Context";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export function BookmarksTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { addr, seek, bookmarks, addBookmark, removeBookmark } = useR2();
  const [label, setLabel] = useState("");
  const [notes, setNotes] = useState("");

  const add = () => {
    if (!addr) return;
    addBookmark({ addr, label: label || addr, notes: notes || undefined });
    setLabel("");
    setNotes("");
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-2 border-b space-y-1.5">
        <div className="flex gap-2 items-center">
          <Input
            placeholder={t("r2_label")}
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="h-7 text-xs flex-1"
          />
          <Button
            size="sm"
            className="h-7 text-xs gap-1 shrink-0"
            disabled={!addr}
            onClick={add}
          >
            <MapPin className="h-3 w-3" />
            {t("r2_add_bookmark")}
          </Button>
        </div>
        <Input
          placeholder={t("r2_notes")}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          className="h-7 text-xs"
        />
        {addr && (
          <div className="text-[10px] text-muted-foreground font-mono">
            {t("r2_current")} {addr}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        {bookmarks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-xs text-muted-foreground gap-2">
            <Bookmark className="h-5 w-5" />
            {t("r2_no_bookmarks")}
          </div>
        ) : (
          bookmarks.map((b) => (
            <div
              key={b.addr}
              className={`px-3 py-2 border-b border-border/30 hover:bg-accent/30 cursor-pointer flex items-start gap-2 group ${
                b.addr === addr ? "bg-primary/10" : ""
              }`}
              onClick={() => seek(b.addr, b.label)}
            >
              <MapPin className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium truncate">{b.label}</div>
                <div className="text-[10px] font-mono text-muted-foreground">{b.addr}</div>
                {b.notes && (
                  <div className="text-[10px] text-muted-foreground mt-0.5">{b.notes}</div>
                )}
              </div>
              <button
                type="button"
                className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-destructive/20 transition-opacity"
                onClick={(e) => { e.stopPropagation(); removeBookmark(b.addr); }}
              >
                <Trash2 className="h-3 w-3 text-destructive" />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
