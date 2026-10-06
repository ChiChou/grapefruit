import type { KeyboardEvent } from "react";

export function fold(e: KeyboardEvent): boolean | undefined {
  if (e.defaultPrevented || e.nativeEvent.isComposing || !(e.ctrlKey || e.metaKey) || !e.altKey || e.shiftKey) return;
  if ((e.target as HTMLElement).closest('input, textarea, select, [contenteditable="true"]')) return;
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  e.preventDefault();
  e.stopPropagation();
  return e.key === "ArrowRight";
}

export function activate(e: KeyboardEvent<HTMLElement>) {
  if (e.target !== e.currentTarget || e.defaultPrevented || e.nativeEvent.isComposing || e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.click();
  }
}
