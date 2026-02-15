"use client"

import { Switch as SwitchPrimitive } from "@base-ui/react/switch"

import { cn } from "@/lib/utils"

function Switch({
  className,
  ...props
}: SwitchPrimitive.Root.Props) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        "data-checked:bg-primary data-unchecked:bg-input focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:aria-invalid:border-destructive/50 dark:data-unchecked:bg-input/80 shrink-0 rounded-full border border-transparent shadow-xs focus-visible:ring-3 aria-invalid:ring-3 h-[18.4px] w-[32px] peer group/switch relative inline-flex items-center transition-all outline-none after:absolute after:-inset-x-3 after:-inset-y-2 data-disabled:cursor-not-allowed data-disabled:opacity-50",
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="bg-background dark:data-unchecked:bg-foreground dark:data-checked:bg-primary-foreground rounded-full size-4 data-checked:translate-x-[calc(100%-2px)] data-unchecked:translate-x-0 pointer-events-none block ring-0 transition-transform"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
