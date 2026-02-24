import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { RotateCcw, Sun, Moon } from "lucide-react";

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
                const label = r.labelKey ? t(r.labelKey) : r.labelFallback;
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
                const label = p.labelKey ? t(p.labelKey) : p.labelFallback;
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
