import { useNavigate } from "react-router";

import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogAction,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

export interface CrashDetail {
  type: string;
  address: string;
  message?: string;
  memory?: { operation: string; address: string };
  context: Record<string, unknown>;
}

const SIMD_REGISTER = /^[qds]\d+$/;

function getGeneralRegisters(
  ctx: Record<string, unknown>,
): [string, string][] {
  return Object.entries(ctx)
    .filter(([key]) => !SIMD_REGISTER.test(key) && key !== "nativeContext")
    .map(([key, value]) => [key, String(value)]);
}

export function CrashDialog({
  detail,
  showRelaunch,
}: {
  detail: CrashDetail | null;
  showRelaunch: boolean;
}) {
  const navigate = useNavigate();

  return (
    <AlertDialog open={detail !== null}>
      <AlertDialogContent size="lg">
        <AlertDialogHeader>
          <AlertDialogTitle>Process Crashed</AlertDialogTitle>
          <AlertDialogDescription>
            The target process encountered a fatal error and will be terminated.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {detail && (
          <ScrollArea className="max-h-[60vh]">
            <div className="space-y-4 text-sm">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground w-20 shrink-0">
                    Type
                  </span>
                  <Badge variant="destructive">{detail.type}</Badge>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground w-20 shrink-0">
                    Address
                  </span>
                  <span className="font-mono text-xs">{detail.address}</span>
                </div>
                {detail.message && (
                  <div className="flex items-start gap-2">
                    <span className="text-muted-foreground w-20 shrink-0">
                      Message
                    </span>
                    <span className="text-xs">{detail.message}</span>
                  </div>
                )}
                {detail.memory && (
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground w-20 shrink-0">
                      Memory
                    </span>
                    <span className="text-xs">
                      <Badge variant="outline" className="mr-1.5">
                        {detail.memory.operation}
                      </Badge>
                      <span className="font-mono">
                        {detail.memory.address}
                      </span>
                    </span>
                  </div>
                )}
              </div>
              <div>
                <span className="text-muted-foreground text-xs font-medium uppercase tracking-wide">
                  Registers
                </span>
                <div className="mt-1.5 grid grid-cols-2 gap-x-6 gap-y-0.5">
                  {getGeneralRegisters(detail.context).map(
                    ([name, value]) => (
                      <div
                        key={name}
                        className="flex items-center gap-2 py-0.5 border-b border-border/30"
                      >
                        <span className="text-muted-foreground font-mono text-xs w-8 shrink-0 text-right">
                          {name}
                        </span>
                        <span className="font-mono text-xs">{value}</span>
                      </div>
                    ),
                  )}
                </div>
              </div>
            </div>
          </ScrollArea>
        )}
        <AlertDialogFooter>
          {showRelaunch && (
            <AlertDialogAction onClick={() => location.reload()}>
              Relaunch
            </AlertDialogAction>
          )}
          <AlertDialogAction variant="outline" onClick={() => navigate("/")}>
            Home
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
