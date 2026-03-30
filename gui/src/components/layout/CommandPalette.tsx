import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import {
  RotateCcw,
  Sun,
  Moon,
  BarChart3,
  Map,
  Library,
  Search,
  Braces,
  GitFork,
  Bookmark,
  LayoutGrid,
  Binary,
  Cpu,
} from "lucide-react";

import {
  CommandDialog,
  Command,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandSeparator,
} from "@/components/ui/command";
import { useSession, Mode } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { getRouteFeatures, getPanelFeatures } from "@/lib/features";
import { useTheme } from "@/components/providers/ThemeProvider";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const { t } = useTranslation();
  const { platform, mode, device, bundle, pid } = useSession();
  const { openSingletonPanel, resetLayout } = useDock();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();

  const target = mode === Mode.App ? bundle : pid;
  const basePath = `/workspace/${platform}/${device}/${mode}/${target}`;

  const routes = getRouteFeatures(platform, mode);
  const panels = getPanelFeatures(platform, mode);

  const close = () => onOpenChange(false);

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <Command>
        <CommandInput placeholder={t("search") + "..."} />
        <CommandList>
          <CommandEmpty>{t("no_results")}</CommandEmpty>

          {routes.length > 0 && (
            <CommandGroup heading={t("navigation")}>
              {routes.map((r) => {
                const Icon = r.icon;
                const label = t(r.label);
                return (
                  <CommandItem
                    key={r.route}
                    onSelect={() => {
                      navigate(`${basePath}/${r.route}`);
                      close();
                    }}
                  >
                    <Icon className="h-4 w-4" />
                    {label}
                  </CommandItem>
                );
              })}
            </CommandGroup>
          )}

          {panels.length > 0 && (
            <CommandGroup heading={t("tools")}>
              {panels.map((p) => {
                const Icon = p.icon;
                const label = t(p.label);
                return (
                  <CommandItem
                    key={p.id}
                    onSelect={() => {
                      openSingletonPanel({
                        id: p.id,
                        component: p.component,
                        title: label,
                        params: p.params,
                      });
                      close();
                    }}
                  >
                    <Icon className="h-4 w-4" />
                    {label}
                  </CommandItem>
                );
              })}
            </CommandGroup>
          )}

          <CommandSeparator />
          <CommandGroup heading={t("r2_decompiler")}>
            {[
              { id: "binaryOverview", component: "binaryOverview", titleKey: "r2_dashboard", icon: BarChart3 },
              { id: "memoryMaps", component: "memoryMaps", titleKey: "r2_memory_maps", icon: Map },
              { id: "binaries", component: "binaries", titleKey: "r2_binaries", icon: Library },
              { id: "r2Search", component: "r2Search", titleKey: "r2_search", icon: Search },
              { id: "typeEditor", component: "typeEditor", titleKey: "r2_type_editor", icon: Braces },
              { id: "xrefGraph", component: "xrefGraph", titleKey: "r2_xref_graph", icon: GitFork },
              { id: "bookmarks", component: "bookmarks", titleKey: "r2_bookmarks", icon: Bookmark },
              { id: "r2SplitView", component: "r2Disasm", titleKey: "r2_disasm_split", icon: Cpu },
              { id: "r2SplitGraph", component: "r2Graph", titleKey: "r2_graph_split", icon: LayoutGrid },
              { id: "r2SplitHex", component: "r2Hex", titleKey: "r2_hex_split", icon: Binary },
            ].map((item) => {
              const Icon = item.icon;
              const label = t(item.titleKey);
              return (
                <CommandItem
                  key={item.id}
                  onSelect={() => {
                    openSingletonPanel({
                      id: item.id,
                      component: item.component,
                      title: label,
                    });
                    close();
                  }}
                >
                  <Icon className="h-4 w-4" />
                  {label}
                </CommandItem>
              );
            })}
          </CommandGroup>

          <CommandSeparator />
          <CommandGroup heading={t("actions")}>
            <CommandItem
              onSelect={() => {
                setTheme(theme === "dark" ? "light" : "dark");
                close();
              }}
            >
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              {t("toggle_dark_mode")}
            </CommandItem>
            <CommandItem
              onSelect={() => {
                resetLayout();
                close();
              }}
            >
              <RotateCcw className="h-4 w-4" />
              {t("reset_layout")}
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  );
}
