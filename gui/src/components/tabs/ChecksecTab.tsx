import { useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Loader2, ShieldCheck, ShieldX, ShieldAlert, Save } from "lucide-react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Platform, useSession } from "@/context/SessionContext";
import { useFruityQuery, useDroidQuery } from "@/lib/queries";

import type { ELFResult, ELFCFI } from "@agent/droid/modules/checksec/elf";
import type { MachOResult } from "@agent/fruity/modules/checksec/macho";

type ELFRow = ELFResult & { name: string; path: string };
type MachORow = MachOResult & { name: string; path: string };

interface Entitlements {
  [key: string]: string | boolean | number | string[];
}

interface EntitlementsPlistResult {
  xml: string;
  value: Entitlements;
}

// Hardened process & hardware memory tagging entitlements
const SECURITY_ENTITLEMENTS: Record<
  string,
  { label: string; secure: (v: unknown) => boolean; desc: string }
> = {
  // Hardened process
  "com.apple.security.hardened-process": {
    label: "Hardened Process",
    secure: (v) => v === true,
    desc: "Opts in to additional security checks",
  },
  "com.apple.security.hardened-process.enhanced-security-version": {
    label: "Enhanced Security Version",
    secure: (v) => typeof v === "number" && v > 0,
    desc: "Opts in to enhanced security protections",
  },
  "com.apple.security.hardened-process.enhanced-security-version-string": {
    label: "Enhanced Security Version (string)",
    secure: (v) => typeof v === "string" && v.length > 0,
    desc: "Opts in to enhanced security protections",
  },
  "com.apple.security.hardened-process.hardened-heap": {
    label: "Hardened Heap",
    secure: (v) => v === true,
    desc: "Type-aware memory allocations",
  },
  "com.apple.security.hardened-process.platform-restrictions": {
    label: "Platform Restrictions",
    secure: (v) => typeof v === "number" && v > 0,
    desc: "Additional runtime security protections",
  },
  "com.apple.security.hardened-process.platform-restrictions-string": {
    label: "Platform Restrictions (string)",
    secure: (v) => typeof v === "string" && v.length > 0,
    desc: "Additional runtime security protections",
  },
  "com.apple.security.hardened-process.dyld-ro": {
    label: "DYLD Read-Only",
    secure: (v) => v === true,
    desc: "Marks dyld internal state as read-only",
  },
  // Hardware memory tagging
  "com.apple.security.hardened-process.checked-allocations": {
    label: "Memory Tagging",
    secure: (v) => v === true,
    desc: "Tags pointers and memory allocations",
  },
  "com.apple.security.hardened-process.checked-allocations.soft-mode": {
    label: "Memory Tagging Soft Mode",
    secure: () => false,
    desc: "Logs faults instead of terminating — weaker enforcement",
  },
  "com.apple.security.hardened-process.checked-allocations.enable-pure-data": {
    label: "Tag Pure Data",
    secure: (v) => v === true,
    desc: "Tags memory containing only data",
  },
  "com.apple.security.hardened-process.checked-allocations.no-tagged-receive": {
    label: "No Tagged Receive",
    secure: (v) => v === true,
    desc: "Prevents receiving tagged memory from other processes",
  },
};

function SecureBadge({ secure, label }: { secure: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${
        secure
          ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
          : "bg-muted text-muted-foreground"
      }`}
    >
      {secure ? (
        <ShieldCheck className="h-3 w-3" />
      ) : (
        <ShieldX className="h-3 w-3" />
      )}
      {label}
    </span>
  );
}

function BoolBadge({
  value,
  trueLabel,
  falseLabel,
}: {
  value: boolean | string;
  trueLabel?: string;
  falseLabel?: string;
}) {
  const isSecure = !!value;
  const label =
    typeof value === "string"
      ? value
      : isSecure
        ? (trueLabel ?? "Yes")
        : (falseLabel ?? "No");
  return <SecureBadge secure={isSecure} label={label} />;
}

function NaBadge() {
  return (
    <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium bg-muted text-muted-foreground">
      N/A
    </span>
  );
}

/** For symbol-dependent checks: show green when detected, N/A when not */
function SymbolBadge({
  value,
  label,
}: {
  value: boolean | string;
  label?: string;
}) {
  if (!value) return <NaBadge />;
  const text = typeof value === "string" ? value : (label ?? "Yes");
  return <SecureBadge secure={true} label={text} />;
}

function RelroBadge({ value }: { value: "full" | "partial" | "none" }) {
  const colors: Record<string, string> = {
    full: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    partial:
      "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    none: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  };
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${colors[value]}`}
    >
      {value === "full" ? (
        <ShieldCheck className="h-3 w-3" />
      ) : value === "partial" ? (
        <ShieldAlert className="h-3 w-3" />
      ) : (
        <ShieldX className="h-3 w-3" />
      )}
      {value}
    </span>
  );
}

function FortifyBadge({
  fortified,
  fortifiable,
}: {
  fortified: number;
  fortifiable: number;
}) {
  if (fortifiable === 0) return <NaBadge />;
  const ratio = fortified / fortifiable;
  const color =
    ratio >= 0.5
      ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
      : ratio > 0
        ? "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
        : "bg-muted text-muted-foreground";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${color}`}
    >
      {fortified}/{fortifiable}
    </span>
  );
}

function CfiBadge({ cfi }: { cfi: ELFCFI }) {
  const parts: string[] = [];
  if (cfi.clang !== "none") parts.push(`clang:${cfi.clang}`);
  if (cfi.shstk) parts.push("SHSTK");
  if (cfi.ibt) parts.push("IBT");
  if (cfi.pac) parts.push("PAC");
  if (cfi.bti) parts.push("BTI");
  if (parts.length === 0) {
    return <SecureBadge secure={false} label="none" />;
  }
  return <SecureBadge secure={true} label={parts.join(", ")} />;
}

function PieBadge({ value }: { value: boolean | "rel" }) {
  if (value === "rel")
    return (
      <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
        <ShieldAlert className="h-3 w-3" />
        REL
      </span>
    );
  return <BoolBadge value={value} />;
}

function ELFTable({ rows, filter }: { rows: ELFRow[]; filter: string }) {
  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (r) =>
        r.name.toLowerCase().includes(q) || r.path.toLowerCase().includes(q),
    );
  }, [rows, filter]);

  return (
    <div className="overflow-auto flex-1">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Module</TableHead>
            <TableHead>RELRO</TableHead>
            <TableHead>NX</TableHead>
            <TableHead>PIE</TableHead>
            <TableHead>Canary</TableHead>
            <TableHead>Stripped</TableHead>
            <TableHead>Fortify</TableHead>
            <TableHead>SafeStack</TableHead>
            <TableHead>CFI</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((row) => (
            <TableRow key={row.path}>
              <TableCell
                className="font-mono text-xs max-w-64 truncate"
                title={row.path}
              >
                {row.name}
              </TableCell>
              <TableCell>
                <RelroBadge value={row.relro} />
              </TableCell>
              <TableCell>
                <BoolBadge value={row.nx} />
              </TableCell>
              <TableCell>
                <PieBadge value={row.pie} />
              </TableCell>
              <TableCell>
                <SymbolBadge value={row.canary} />
              </TableCell>
              <TableCell>
                <BoolBadge
                  value={row.stripped}
                  trueLabel="Yes"
                  falseLabel="No"
                />
              </TableCell>
              <TableCell>
                <FortifyBadge
                  fortified={row.fortify.fortified}
                  fortifiable={row.fortify.fortifiable}
                />
              </TableCell>
              <TableCell>
                <BoolBadge value={row.safeStack} />
              </TableCell>
              <TableCell>
                <CfiBadge cfi={row.cfi} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// -- Mach-O Table --

function MachOTable({ rows, filter }: { rows: MachORow[]; filter: string }) {
  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (r) =>
        r.name.toLowerCase().includes(q) || r.path.toLowerCase().includes(q),
    );
  }, [rows, filter]);

  return (
    <div className="overflow-auto flex-1">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Module</TableHead>
            <TableHead>PIE</TableHead>
            <TableHead>NX</TableHead>
            <TableHead>Canary</TableHead>
            <TableHead>ARC</TableHead>
            <TableHead>Code Sign</TableHead>
            <TableHead>Encryption</TableHead>
            <TableHead>Stripped</TableHead>
            <TableHead>Fortify</TableHead>
            <TableHead>PAC</TableHead>
            <TableHead>Secure Malloc</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((row) => (
            <TableRow key={row.path}>
              <TableCell
                className="font-mono text-xs max-w-64 truncate"
                title={row.path}
              >
                {row.name}
              </TableCell>
              <TableCell>
                <BoolBadge value={row.pie} />
              </TableCell>
              <TableCell>
                <BoolBadge value={row.nx} />
              </TableCell>
              <TableCell>
                <SymbolBadge value={row.canary} />
              </TableCell>
              <TableCell>
                <SymbolBadge value={row.arc} />
              </TableCell>
              <TableCell>
                <SymbolBadge value={row.codesign} />
              </TableCell>
              <TableCell>
                <EncryptionBadge value={row.encryption} />
              </TableCell>
              <TableCell>
                <BoolBadge
                  value={row.stripped}
                  trueLabel="Yes"
                  falseLabel="No"
                />
              </TableCell>
              <TableCell>
                <FortifyBadge
                  fortified={row.fortify.fortified}
                  fortifiable={row.fortify.fortifiable}
                />
              </TableCell>
              <TableCell>
                <BoolBadge value={row.pac} />
              </TableCell>
              <TableCell>
                <BoolBadge value={row.secureMalloc} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function EncryptionBadge({ value }: { value: boolean | string }) {
  if (value === true) return <SecureBadge secure={true} label="Encrypted" />;
  if (value === false) return <SecureBadge secure={false} label="No" />;
  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
      <ShieldAlert className="h-3 w-3" />
      {value}
    </span>
  );
}

// -- Entitlements Panel --

function EntitlementsPanel({ data }: { data: EntitlementsPlistResult }) {
  const ents = data.value;
  if (!ents || Object.keys(ents).length === 0) {
    return (
      <div className="text-sm text-muted-foreground p-4">
        No entitlements found for main executable.
      </div>
    );
  }

  // Split into security-relevant and other
  const securityEntries: {
    key: string;
    value: unknown;
    meta: (typeof SECURITY_ENTITLEMENTS)[string];
  }[] = [];

  for (const [key, value] of Object.entries(ents)) {
    const meta = SECURITY_ENTITLEMENTS[key];
    if (meta) {
      securityEntries.push({ key, value, meta });
    }
  }

  if (securityEntries.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">
        No hardened process or memory tagging entitlements found.
      </div>
    );
  }

  return (
    <div>
      <h3 className="text-sm font-medium mb-2 flex items-center gap-1.5">
        <ShieldCheck className="h-4 w-4" />
        Security Entitlements
      </h3>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Entitlement</TableHead>
            <TableHead>Value</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Description</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {securityEntries.map(({ key, value, meta }) => {
            const isSecure = meta.secure(value);
            return (
              <TableRow key={key}>
                <TableCell className="font-mono text-xs">
                  {meta.label}
                </TableCell>
                <TableCell className="text-xs">
                  {typeof value === "boolean" ? (
                    <Badge variant={value ? "default" : "secondary"}>
                      {String(value)}
                    </Badge>
                  ) : (
                    <span className="font-mono">{String(value)}</span>
                  )}
                </TableCell>
                <TableCell>
                  <SecureBadge
                    secure={isSecure}
                    label={isSecure ? "Secure" : "Insecure"}
                  />
                </TableCell>
                <TableCell className="text-xs text-muted-foreground max-w-80">
                  {meta.desc}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

// -- Main component --

export function ChecksecTab() {
  const { t } = useTranslation();
  const { platform, bundle } = useSession();
  const isFruity = platform === Platform.Fruity;
  const [filter, setFilter] = useState("");

  const fruityResult = useFruityQuery(
    ["checksec", "all"],
    (api) => api.checksec.all(),
    { enabled: isFruity },
  );

  const droidResult = useDroidQuery(
    ["checksec", "all"],
    (api) => api.checksec.all(),
    { enabled: !isFruity },
  );

  const entitlementsResult = useFruityQuery(
    ["entitlements", ""],
    (api) => api.entitlements.plist(),
    { enabled: isFruity },
  );

  const { data, isLoading } = isFruity ? fruityResult : droidResult;

  const handleDownload = () => {
    const exportData = isFruity
      ? {
          modules: data,
          entitlements: entitlementsResult.data,
        }
      : { modules: data };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${bundle ?? "checksec"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-2 p-2 border-b shrink-0">
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t("search")}
          className="h-8 max-w-xs"
        />
        <Button
          variant="outline"
          size="sm"
          className="h-8"
          onClick={handleDownload}
          disabled={!data}
        >
          <Save className="h-4 w-4 mr-1" />
        </Button>
        <span className="text-xs text-muted-foreground ml-auto">
          {(data as unknown[])?.length ?? 0} modules
        </span>
      </div>

      <div className="flex-1 overflow-auto">
        {/* Entitlements section (Apple only) */}
        {isFruity && entitlementsResult.data && (
          <div className="border-b p-4">
            <EntitlementsPanel
              data={
                entitlementsResult.data as unknown as EntitlementsPlistResult
              }
            />
          </div>
        )}

        {/* Checksec table */}
        {isFruity ? (
          <MachOTable rows={(data as MachORow[]) ?? []} filter={filter} />
        ) : (
          <ELFTable rows={(data as ELFRow[]) ?? []} filter={filter} />
        )}
      </div>
    </div>
  );
}
