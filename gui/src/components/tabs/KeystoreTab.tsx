import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { useDroidRpcQuery } from "@/lib/queries";

import type { KeystoreAlias, KeyInfo } from "@agent/droid/modules/keystore";

const ITEM_HEIGHT = 56;

function decodePurposes(purposes: number): string[] {
  const result: string[] = [];
  if (purposes & 1) result.push("ENCRYPT");
  if (purposes & 2) result.push("DECRYPT");
  if (purposes & 4) result.push("SIGN");
  if (purposes & 8) result.push("VERIFY");
  return result.length > 0 ? result : ["NONE"];
}

function decodeOrigin(origin: number): string {
  switch (origin) {
    case 1:
      return "GENERATED";
    case 2:
      return "IMPORTED";
    case 4:
      return "UNKNOWN";
    default:
      return `OTHER (${origin})`;
  }
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mt-6 mb-2 first:mt-0">
      {children}
    </div>
  );
}

function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start py-1.5 border-b border-border/50">
      <div className="text-xs text-muted-foreground w-48 shrink-0">
        {label}
      </div>
      <div className="text-sm flex-1 min-w-0">{children}</div>
    </div>
  );
}

function BoolBadge({ value }: { value: boolean | null }) {
  if (value === null)
    return <span className="text-xs text-muted-foreground">N/A</span>;
  return (
    <Badge
      variant={value ? "default" : "secondary"}
      className="text-[10px] px-1.5 py-0"
    >
      {value ? "Yes" : "No"}
    </Badge>
  );
}

function ArrayDisplay({ items }: { items: string[] }) {
  if (items.length === 0)
    return <span className="text-xs text-muted-foreground">None</span>;
  return (
    <div className="flex gap-1 flex-wrap">
      {items.map((item) => (
        <Badge
          key={item}
          variant="outline"
          className="text-[10px] px-1.5 py-0 font-mono"
        >
          {item}
        </Badge>
      ))}
    </div>
  );
}

// --- Detail pane ---

function KeyDetail({
  alias,
  entryType,
}: {
  alias: string;
  entryType: string;
}) {
  const { t } = useTranslation();

  const {
    data: keyInfo,
    isLoading,
    error,
  } = useDroidRpcQuery<KeyInfo | null>(
    ["keystoreInfo", alias],
    (api) => api.keystore.info(alias),
  );

  if (error) {
    return (
      <div className="h-full p-4 overflow-auto">
        <Alert variant="destructive">
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>{(error as Error)?.message}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="h-full p-4 overflow-auto">
        <div className="space-y-3">
          <Skeleton className="h-4 w-48" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-full" />
        </div>
      </div>
    );
  }

  if (!keyInfo) {
    return (
      <div className="h-full p-4 overflow-auto">
        <div className="text-sm text-muted-foreground">{t("no_data")}</div>
      </div>
    );
  }

  return (
    <div className="h-full p-4 overflow-auto">
      <div className="max-w-2xl space-y-1">
        <SectionLabel>{t("key_properties")}</SectionLabel>
        <InfoRow label={t("alias")}>{keyInfo.alias}</InfoRow>
        <InfoRow label={t("hook_algorithm")}>{keyInfo.algorithm}</InfoRow>
        <InfoRow label={t("key_size")}>{keyInfo.keySize} bits</InfoRow>
        <InfoRow label={t("entry_type")}>
          <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
            {entryType}
          </Badge>
        </InfoRow>
        <InfoRow label={t("origin")}>
          {decodeOrigin(keyInfo.origin)}
        </InfoRow>
        <InfoRow label={t("purposes")}>
          <ArrayDisplay items={decodePurposes(keyInfo.purposes)} />
        </InfoRow>

        <SectionLabel>{t("crypto_config")}</SectionLabel>
        <InfoRow label={t("block_modes")}>
          <ArrayDisplay items={keyInfo.blockModes} />
        </InfoRow>
        <InfoRow label={t("digests")}>
          <ArrayDisplay items={keyInfo.digests} />
        </InfoRow>
        <InfoRow label={t("encryption_paddings")}>
          <ArrayDisplay items={keyInfo.encryptionPaddings} />
        </InfoRow>
        <InfoRow label={t("signature_paddings")}>
          <ArrayDisplay items={keyInfo.signaturePaddings} />
        </InfoRow>

        <SectionLabel>{t("security_properties")}</SectionLabel>
        <InfoRow label={t("inside_secure_hardware")}>
          <BoolBadge value={keyInfo.isInsideSecureHardware} />
        </InfoRow>
        <InfoRow label={t("user_auth_required")}>
          <BoolBadge value={keyInfo.isUserAuthenticationRequired} />
        </InfoRow>
        <InfoRow label={t("auth_validity_seconds")}>
          {keyInfo.userAuthenticationValidityDurationSeconds}
        </InfoRow>
        <InfoRow label={t("auth_enforced_by_hardware")}>
          <BoolBadge
            value={
              keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware
            }
          />
        </InfoRow>
        <InfoRow label={t("biometric_invalidation")}>
          <BoolBadge value={keyInfo.isInvalidatedByBiometricEnrollment} />
        </InfoRow>
        <InfoRow label={t("trusted_presence_required")}>
          <BoolBadge value={keyInfo.isTrustedUserPresenceRequired} />
        </InfoRow>
        <InfoRow label={t("user_confirmation_required")}>
          <BoolBadge value={keyInfo.isUserConfirmationRequired} />
        </InfoRow>
        <InfoRow label={t("auth_valid_on_body")}>
          <BoolBadge
            value={keyInfo.isUserAuthenticationValidWhileOnBody}
          />
        </InfoRow>

        {(keyInfo.keyValidityStart ||
          keyInfo.keyValidityForOriginationEnd ||
          keyInfo.keyValidityForConsumptionEnd) && (
          <>
            <SectionLabel>{t("validity")}</SectionLabel>
            {keyInfo.keyValidityStart && (
              <InfoRow label={t("validity_start")}>
                {keyInfo.keyValidityStart}
              </InfoRow>
            )}
            {keyInfo.keyValidityForOriginationEnd && (
              <InfoRow label={t("validity_origination_end")}>
                {keyInfo.keyValidityForOriginationEnd}
              </InfoRow>
            )}
            {keyInfo.keyValidityForConsumptionEnd && (
              <InfoRow label={t("validity_consumption_end")}>
                {keyInfo.keyValidityForConsumptionEnd}
              </InfoRow>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// --- List pane ---

function AliasRow({
  index,
  style,
  items,
  selected,
  onClick,
}: RowComponentProps<{
  items: KeystoreAlias[];
  selected: string | null;
  onClick: (alias: string) => void;
}>) {
  const item = items[index];
  const isSelected = item.alias === selected;

  return (
    <button
      type="button"
      className={`w-full text-left px-4 py-2 border-b border-border hover:bg-accent ${isSelected ? "bg-accent" : ""}`}
      style={style}
      onClick={() => onClick(item.alias)}
    >
      <div className="flex items-center justify-between">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium truncate">{item.alias}</div>
          <div className="text-xs text-muted-foreground font-mono truncate">
            {item.algorithm ?? "N/A"}
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0 ml-2">
          <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
            {item.entryType}
          </Badge>
        </div>
      </div>
    </button>
  );
}

// --- Main tab ---

export function KeystoreTab() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const { data: keys = [], isLoading } = useDroidRpcQuery<KeystoreAlias[]>(
    ["keystoreAliases"],
    (api) => api.keystore.aliases(),
  );

  const filtered = useMemo(() => {
    if (!search.trim()) return keys;
    const query = search.toLowerCase();
    return keys.filter(
      (k) =>
        k.alias.toLowerCase().includes(query) ||
        k.algorithm?.toLowerCase().includes(query) ||
        k.entryType.toLowerCase().includes(query),
    );
  }, [keys, search]);

  const selectedEntry = keys.find((k) => k.alias === selected);

  const listPane = (
    <div className="h-full flex flex-col">
      <div className="p-3 space-y-2 border-b border-border">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="text-xs text-muted-foreground">
          {filtered.length} / {keys.length}
        </div>
      </div>
      <div className="flex-1 min-h-0">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("loading")}...
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_keystore_aliases")}
          </div>
        ) : (
          <div className="flex h-full">
            <List
              rowComponent={AliasRow}
              rowCount={filtered.length}
              rowHeight={ITEM_HEIGHT}
              rowProps={{
                items: filtered,
                selected,
                onClick: setSelected,
              }}
            />
          </div>
        )}
      </div>
    </div>
  );

  if (!selected || !selectedEntry) {
    return listPane;
  }

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="keystore-tab-split"
    >
      <ResizablePanel defaultSize="35%" minSize="20%">
        {listPane}
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel>
        <KeyDetail
          alias={selected}
          entryType={selectedEntry.entryType}
        />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
