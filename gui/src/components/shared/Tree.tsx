import { createContext, useContext, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { fold } from "@/lib/keyboard";
import type { ReactNode, KeyboardEvent } from "react";

const Context = createContext<{ open: boolean; version: number } | null>(null);

export function useBranch(initial: boolean, reset?: string) {
  const [open, setOpen] = useState(initial);
  const command = useContext(Context);
  const prev = useRef<{ command: typeof command; reset?: string } | null>(null);
  useEffect(() => {
    if (command && prev.current?.command !== command) setOpen(command.open);
    else if (reset !== undefined && prev.current?.reset !== reset) setOpen(initial);
    prev.current = { command, reset };
  }, [command, initial, reset]);
  return [open, setOpen] as const;
}

export function Tree({ children, label, onExpand, onCollapse, shortcuts = true }: {
  children: ReactNode;
  label: string;
  onExpand?: () => void;
  onCollapse?: () => void;
  shortcuts?: boolean;
}) {
  const { t } = useTranslation();
  const host = useRef<HTMLDivElement>(null);
  const focused = useRef<HTMLElement | null>(null);
  const [command, setCommand] = useState<{ open: boolean; version: number } | null>(null);
  const rows = () => [...(host.current?.querySelectorAll<HTMLElement>('[role="treeitem"]') ?? [])];
  useEffect(() => {
    const root = host.current;
    if (!root) return;
    const sync = () => {
      const items = rows();
      const active = items.find(row => row === document.activeElement) ?? items.find(row => row.tabIndex === 0) ?? items[0];
      items.forEach(row => { row.tabIndex = row === active ? 0 : -1; });
      if (focused.current && !root.contains(focused.current) && document.activeElement === document.body) active?.focus();
    };
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(root, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);
  const key = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.defaultPrevented || e.nativeEvent.isComposing) return;
    const target = e.target as HTMLElement;
    if (target.closest('input, textarea, select, [contenteditable="true"]')) return;
    const row = target.closest<HTMLElement>('[role="treeitem"]');
    if (!row || !host.current?.contains(row)) return;
    const items = rows();
    const index = items.indexOf(row);
    const level = Number(row.getAttribute("aria-level"));
    const toggle = !row.hasAttribute("aria-expanded") ? null : row.matches("[data-tree-toggle]") ? row as HTMLButtonElement : row.querySelector<HTMLButtonElement>('[data-tree-toggle]');
    const open = row.getAttribute("aria-expanded") === "true";
    let next: HTMLElement | undefined;
    const expand = shortcuts ? fold(e) : undefined;
    if (expand !== undefined) {
      // Keep focus attached to a surviving row when folding the whole tree.
      if (!expand) items[0]?.focus();
      if (expand && onExpand) onExpand();
      else if (!expand && onCollapse) onCollapse();
      else setCommand(old => ({ open: expand, version: (old?.version ?? 0) + 1 }));
      return;
    }
    if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    switch (e.key) {
      case "ArrowDown": next = items[index + 1]; break;
      case "ArrowUp": next = items[index - 1]; break;
      case "Home": next = items[0]; break;
      case "End": next = items.at(-1); break;
      case "ArrowRight":
        if (toggle && !open) toggle.click();
        else if (open && Number(items[index + 1]?.getAttribute("aria-level")) > level) next = items[index + 1];
        break;
      case "ArrowLeft":
        if (toggle && open) toggle.click();
        else next = items.slice(0, index).reverse().find(item => Number(item.getAttribute("aria-level")) < level);
        break;
      case "Enter": case " ":
        if (target === row) row.click();
        else if (toggle?.contains(target)) toggle.click();
        break;
      default: return;
    }
    e.preventDefault();
    e.stopPropagation();
    next?.focus();
    next?.scrollIntoView({ block: "nearest" });
  };
  return <Context value={command}><div ref={host} role="tree" aria-label={label} title={t(shortcuts ? "tree_keys" : "tree_arrows")}
    aria-keyshortcuts={shortcuts ? "Control+Alt+ArrowRight Meta+Alt+ArrowRight Control+Alt+ArrowLeft Meta+Alt+ArrowLeft" : undefined} onKeyDown={key}
    onFocusCapture={e => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('[role="treeitem"]');
      focused.current = row;
      rows().forEach(item => { item.tabIndex = item === row ? 0 : -1; });
    }} onBlurCapture={e => {
      if (e.relatedTarget && !e.currentTarget.contains(e.relatedTarget as Node)) focused.current = null;
    }}>{children}</div></Context>;
}
