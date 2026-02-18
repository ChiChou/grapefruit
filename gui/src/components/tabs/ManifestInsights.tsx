import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { ShieldAlert, ShieldCheck, Info, AlertTriangle, Lock, Unlock, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";

type Severity = "high" | "medium" | "info" | "ok";

interface Insight {
  id: string;
  severity: Severity;
  title: string;
  description: string;
}

interface PermissionEntry {
  name: string;
  dangerous: boolean;
  descKey?: string;
}

// Maps android.permission.FOO → translation key "perm_desc_FOO"
const DANGEROUS_PERM_DESC_KEYS: Record<string, string> = {
  "android.permission.CAMERA": "perm_desc_CAMERA",
  "android.permission.RECORD_AUDIO": "perm_desc_RECORD_AUDIO",
  "android.permission.READ_CONTACTS": "perm_desc_READ_CONTACTS",
  "android.permission.WRITE_CONTACTS": "perm_desc_WRITE_CONTACTS",
  "android.permission.READ_CALL_LOG": "perm_desc_READ_CALL_LOG",
  "android.permission.WRITE_CALL_LOG": "perm_desc_WRITE_CALL_LOG",
  "android.permission.PROCESS_OUTGOING_CALLS": "perm_desc_PROCESS_OUTGOING_CALLS",
  "android.permission.READ_CALENDAR": "perm_desc_READ_CALENDAR",
  "android.permission.WRITE_CALENDAR": "perm_desc_WRITE_CALENDAR",
  "android.permission.ACCESS_FINE_LOCATION": "perm_desc_ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION": "perm_desc_ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_BACKGROUND_LOCATION": "perm_desc_ACCESS_BACKGROUND_LOCATION",
  "android.permission.READ_PHONE_STATE": "perm_desc_READ_PHONE_STATE",
  "android.permission.READ_PHONE_NUMBERS": "perm_desc_READ_PHONE_NUMBERS",
  "android.permission.CALL_PHONE": "perm_desc_CALL_PHONE",
  "android.permission.ANSWER_PHONE_CALLS": "perm_desc_ANSWER_PHONE_CALLS",
  "android.permission.ADD_VOICEMAIL": "perm_desc_ADD_VOICEMAIL",
  "android.permission.USE_SIP": "perm_desc_USE_SIP",
  "android.permission.SEND_SMS": "perm_desc_SEND_SMS",
  "android.permission.RECEIVE_SMS": "perm_desc_RECEIVE_SMS",
  "android.permission.READ_SMS": "perm_desc_READ_SMS",
  "android.permission.RECEIVE_WAP_PUSH": "perm_desc_RECEIVE_WAP_PUSH",
  "android.permission.RECEIVE_MMS": "perm_desc_RECEIVE_MMS",
  "android.permission.BODY_SENSORS": "perm_desc_BODY_SENSORS",
  "android.permission.BODY_SENSORS_BACKGROUND": "perm_desc_BODY_SENSORS_BACKGROUND",
  "android.permission.READ_EXTERNAL_STORAGE": "perm_desc_READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE": "perm_desc_WRITE_EXTERNAL_STORAGE",
  "android.permission.MANAGE_EXTERNAL_STORAGE": "perm_desc_MANAGE_EXTERNAL_STORAGE",
  "android.permission.ACCESS_MEDIA_LOCATION": "perm_desc_ACCESS_MEDIA_LOCATION",
  "android.permission.SYSTEM_ALERT_WINDOW": "perm_desc_SYSTEM_ALERT_WINDOW",
  "android.permission.REQUEST_INSTALL_PACKAGES": "perm_desc_REQUEST_INSTALL_PACKAGES",
  "android.permission.GET_ACCOUNTS": "perm_desc_GET_ACCOUNTS",
  "android.permission.BLUETOOTH_SCAN": "perm_desc_BLUETOOTH_SCAN",
  "android.permission.BLUETOOTH_CONNECT": "perm_desc_BLUETOOTH_CONNECT",
  "android.permission.UWB_RANGING": "perm_desc_UWB_RANGING",
  "android.permission.ACTIVITY_RECOGNITION": "perm_desc_ACTIVITY_RECOGNITION",
  "android.permission.POST_NOTIFICATIONS": "perm_desc_POST_NOTIFICATIONS",
};

const ANDROID_NS = "http://schemas.android.com/apk/res/android";

function getAndroidAttr(el: Element | null | undefined, name: string): string | null {
  if (!el) return null;
  return (
    el.getAttributeNS(ANDROID_NS, name) ??
    el.getAttribute(`android:${name}`) ??
    el.getAttribute(name)
  );
}

/** Normalise compiled-manifest hex booleans (0x00000000 / 0xffffffff) to "true"/"false" */
function normaliseBool(value: string | null): string | null {
  if (value === null) return null;
  const v = value.toLowerCase();
  if (v === "true" || v === "0xffffffff") return "true";
  if (v === "false" || v === "0x00000000" || v === "0x0") return "false";
  return value;
}

function parseManifestInsights(
  xml: string,
  t: TFunction
): { insights: Insight[]; permissions: PermissionEntry[]; packageName: string | null } {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, "application/xml");
  const insights: Insight[] = [];

  const manifest = doc.querySelector("manifest");
  const packageName = manifest?.getAttribute("package") ?? null;
  const application = doc.querySelector("application");

  // android:debuggable
  const debuggable = normaliseBool(getAndroidAttr(application, "debuggable"));
  if (debuggable === "true") {
    insights.push({
      id: "debuggable",
      severity: "high",
      title: t("manifest_debuggable_on_title"),
      description: t("manifest_debuggable_on_desc"),
    });
  } else {
    insights.push({
      id: "debuggable",
      severity: "ok",
      title: t("manifest_debuggable_off_title"),
      description: t("manifest_debuggable_off_desc"),
    });
  }

  // android:allowBackup
  const allowBackup = normaliseBool(getAndroidAttr(application, "allowBackup"));
  if (allowBackup !== "false") {
    insights.push({
      id: "allowBackup",
      severity: "medium",
      title: t("manifest_allowbackup_on_title"),
      description:
        allowBackup === null
          ? t("manifest_allowbackup_on_default_desc")
          : t("manifest_allowbackup_on_explicit_desc"),
    });
  } else {
    insights.push({
      id: "allowBackup",
      severity: "ok",
      title: t("manifest_allowbackup_off_title"),
      description: t("manifest_allowbackup_off_desc"),
    });
  }

  // android:usesCleartextTraffic
  const cleartext = normaliseBool(getAndroidAttr(application, "usesCleartextTraffic"));
  if (cleartext === "true") {
    insights.push({
      id: "cleartext",
      severity: "high",
      title: t("manifest_cleartext_title"),
      description: t("manifest_cleartext_desc"),
    });
  }

  // android:networkSecurityConfig
  const nsc = getAndroidAttr(application, "networkSecurityConfig");
  if (!nsc) {
    insights.push({
      id: "nsc",
      severity: "info",
      title: t("manifest_nsc_title"),
      description: t("manifest_nsc_desc"),
    });
  }

  // Permissions
  const permissionElements = doc.querySelectorAll("uses-permission");
  const permissions: PermissionEntry[] = Array.from(permissionElements).map((el) => {
    const name = getAndroidAttr(el, "name") ?? "";
    const descKey = DANGEROUS_PERM_DESC_KEYS[name];
    return { name, dangerous: !!descKey, descKey };
  });

  const dangerousCount = permissions.filter((p) => p.dangerous).length;
  if (dangerousCount >= 8) {
    insights.push({
      id: "permissions",
      severity: "medium",
      title: t("manifest_perms_excessive_title", { count: dangerousCount }),
      description: t("manifest_perms_excessive_desc", { count: dangerousCount }),
    });
  } else if (dangerousCount > 0) {
    insights.push({
      id: "permissions",
      severity: "info",
      title: t("manifest_perms_some_title", { count: dangerousCount }),
      description: t("manifest_perms_some_desc", { count: dangerousCount }),
    });
  } else if (permissions.length > 0) {
    insights.push({
      id: "permissions",
      severity: "ok",
      title: t("manifest_perms_none_title"),
      description: t("manifest_perms_none_desc", { count: permissions.length }),
    });
  }

  return { insights, permissions, packageName };
}

const SEVERITY_CONFIG: Record<
  Severity,
  {
    icon: React.ComponentType<{ className?: string }>;
    badge: string;
    labelKey: string;
  }
> = {
  high: {
    icon: ShieldAlert,
    badge: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    labelKey: "severity_high",
  },
  medium: {
    icon: AlertTriangle,
    badge: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    labelKey: "severity_medium",
  },
  info: {
    icon: Info,
    badge: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    labelKey: "severity_info",
  },
  ok: {
    icon: ShieldCheck,
    badge: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    labelKey: "severity_ok",
  },
};

function InsightCard({ insight }: { insight: Insight }) {
  const { t } = useTranslation();
  const cfg = SEVERITY_CONFIG[insight.severity];
  const Icon = cfg.icon;
  return (
    <div className="flex gap-3 rounded-lg border p-4">
      <div className={`mt-0.5 shrink-0 rounded p-1.5 ${cfg.badge}`}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-1">
          <span className="font-medium text-sm">{insight.title}</span>
          <span
            className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${cfg.badge}`}
          >
            {t(cfg.labelKey)}
          </span>
        </div>
        <p className="text-xs text-muted-foreground leading-relaxed">{insight.description}</p>
      </div>
    </div>
  );
}

function PermissionRow({ perm }: { perm: PermissionEntry }) {
  const { t } = useTranslation();
  const shortName = perm.name.replace(/^android\.permission\./, "");
  return (
    <div className="flex items-start gap-3 py-2.5 border-b last:border-b-0">
      <div className="mt-0.5 shrink-0">
        {perm.dangerous ? (
          <Unlock className="h-4 w-4 text-amber-500" />
        ) : (
          <Lock className="h-4 w-4 text-muted-foreground" />
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono font-medium">{shortName}</span>
          {perm.dangerous && (
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0 border-amber-400 text-amber-600 dark:text-amber-400"
            >
              {t("manifest_perm_dangerous")}
            </Badge>
          )}
        </div>
        {perm.descKey ? (
          <p className="text-xs text-muted-foreground mt-0.5">{t(perm.descKey)}</p>
        ) : (
          <p className="text-xs text-muted-foreground mt-0.5 font-mono break-all">{perm.name}</p>
        )}
      </div>
    </div>
  );
}

export function ManifestInsights({
  xml,
  permsOpen,
  setPermsOpen,
}: {
  xml: string;
  permsOpen: boolean;
  setPermsOpen: React.Dispatch<React.SetStateAction<boolean>>;
}) {
  const { t } = useTranslation();
  const { insights, permissions } = parseManifestInsights(xml, t);

  const highCount = insights.filter((i) => i.severity === "high").length;
  const mediumCount = insights.filter((i) => i.severity === "medium").length;
  const dangerousPerms = permissions.filter((p) => p.dangerous);

  return (
    <div className="h-full overflow-auto">
      <div className="p-4 max-w-3xl mx-auto space-y-6">
        {/* Summary bar */}
        <div className="flex items-center gap-4 rounded-lg border p-3 bg-muted/30">
          <div className="flex items-center gap-1.5 text-sm">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500 inline-block" />
            <span className="font-medium">{highCount}</span>
            <span className="text-muted-foreground">{t("manifest_summary_high")}</span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500 inline-block" />
            <span className="font-medium">{mediumCount}</span>
            <span className="text-muted-foreground">{t("manifest_summary_medium")}</span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <Unlock className="h-3.5 w-3.5 text-amber-500" />
            <span className="font-medium">{dangerousPerms.length}</span>
            <span className="text-muted-foreground">{t("manifest_summary_dangerous_perms")}</span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <Lock className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-medium">{permissions.length - dangerousPerms.length}</span>
            <span className="text-muted-foreground">{t("manifest_summary_normal_perms")}</span>
          </div>
        </div>

        {/* Security findings */}
        <section>
          <h2 className="text-sm font-semibold mb-3 text-foreground">
            {t("manifest_security_findings")}
          </h2>
          <div className="space-y-2">
            {insights.map((insight) => (
              <InsightCard key={insight.id} insight={insight} />
            ))}
          </div>
        </section>

        {/* Permissions */}
        <section>
          <button
            className="flex items-center gap-1.5 w-full text-left mb-3 group"
            onClick={() => setPermsOpen((o) => !o)}
          >
            <ChevronRight
              className={`h-4 w-4 text-muted-foreground transition-transform duration-150 ${permsOpen ? "rotate-90" : ""}`}
            />
            <h2 className="text-sm font-semibold text-foreground group-hover:text-foreground/80">
              {permissions.length > 0
                ? t("manifest_declared_permissions_count", { count: permissions.length })
                : t("manifest_declared_permissions")}
            </h2>
          </button>
          {permsOpen && (
            permissions.length > 0 ? (
              <div className="rounded-lg border px-4 divide-y-0">
                {[...permissions]
                  .sort((a, b) => (b.dangerous ? 1 : 0) - (a.dangerous ? 1 : 0))
                  .map((perm) => (
                    <PermissionRow key={perm.name} perm={perm} />
                  ))}
              </div>
            ) : (
              <div className="rounded-lg border p-4 text-sm text-muted-foreground">
                {t("manifest_no_permissions_desc")}
              </div>
            )
          )}
        </section>
      </div>
    </div>
  );
}
