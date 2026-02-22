import { useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import {
  ShieldAlert,
  ShieldCheck,
  Info,
  AlertTriangle,
  Lock,
  Unlock,
  ChevronRight,
  Globe,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";

type Severity = "high" | "medium" | "info" | "ok";

interface Insight {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  list?: string[];
}

interface PermissionEntry {
  key: string;
  label: string;
  description: string;
  usageDescription: string;
  sensitive: boolean;
}

interface URLSchemeEntry {
  name?: string;
  schemes: string[];
  role?: string;
}

const SENSITIVE_PERMISSIONS = new Set([
  "NSCameraUsageDescription",
  "NSMicrophoneUsageDescription",
  "NSContactsUsageDescription",
  "NSFaceIDUsageDescription",
  "NSLocationAlwaysAndWhenInUseUsageDescription",
  "NSLocationUsageDescription",
  "NSLocationWhenInUseUsageDescription",
  "NSLocationAlwaysUsageDescription",
  "NSHealthClinicalHealthRecordsShareUsageDescription",
  "NSHealthShareUsageDescription",
  "NSHealthUpdateUsageDescription",
  "NSPhotoLibraryUsageDescription",
  "NSPhotoLibraryAddUsageDescription",
]);

const PERMISSION_LABELS: Record<string, string> = {
  NSBluetoothAlwaysUsageDescription: "Bluetooth Always",
  NSBluetoothPeripheralUsageDescription: "Bluetooth Peripheral",
  NSCalendarsUsageDescription: "Calendars",
  NSRemindersUsageDescription: "Reminders",
  NSCameraUsageDescription: "Camera",
  NSMicrophoneUsageDescription: "Microphone",
  NSContactsUsageDescription: "Contacts",
  NSFaceIDUsageDescription: "Face ID",
  NSDesktopFolderUsageDescription: "Desktop Folder",
  NSDocumentsFolderUsageDescription: "Documents Folder",
  NSDownloadsFolderUsageDescription: "Downloads Folder",
  NSNetworkVolumesUsageDescription: "Network Volumes",
  NSRemovableVolumesUsageDescription: "Removable Volumes",
  NSFileProviderPresenceUsageDescription: "File Provider Presence",
  NSFileProviderDomainUsageDescription: "File Provider Domain",
  NSHealthClinicalHealthRecordsShareUsageDescription: "Health Records",
  NSHealthShareUsageDescription: "Health Share",
  NSHealthUpdateUsageDescription: "Health Update",
  NSHomeKitUsageDescription: "HomeKit",
  NSLocationAlwaysAndWhenInUseUsageDescription: "Location Always & When In Use",
  NSLocationUsageDescription: "Location",
  NSLocationWhenInUseUsageDescription: "Location When In Use",
  NSLocationAlwaysUsageDescription: "Location Always",
  NSAppleMusicUsageDescription: "Apple Music / Media Library",
  NSMotionUsageDescription: "Motion & Fitness",
  NFCReaderUsageDescription: "NFC Reader",
  NSPhotoLibraryAddUsageDescription: "Photo Library (Add Only)",
  NSPhotoLibraryUsageDescription: "Photo Library",
  NSAppleScriptEnabled: "AppleScript",
  NSAppleEventsUsageDescription: "Apple Events",
  NSSystemAdministrationUsageDescription: "System Administration",
  NSSiriUsageDescription: "Siri",
  NSSpeechRecognitionUsageDescription: "Speech Recognition",
  NSVideoSubscriberAccountUsageDescription: "Video Subscriber Account",
  UIRequiresPersistentWiFi: "Persistent Wi-Fi",
};

const PERMISSION_DESCRIPTIONS: Record<string, string> = {
  NSBluetoothAlwaysUsageDescription: "Access Bluetooth at all times",
  NSBluetoothPeripheralUsageDescription: "Connect to Bluetooth peripherals",
  NSCalendarsUsageDescription: "Access calendar data",
  NSRemindersUsageDescription: "Access reminders",
  NSCameraUsageDescription: "Capture photos and video",
  NSMicrophoneUsageDescription: "Record audio",
  NSContactsUsageDescription: "Read contacts",
  NSFaceIDUsageDescription: "Authenticate with Face ID",
  NSDesktopFolderUsageDescription: "Access Desktop folder",
  NSDocumentsFolderUsageDescription: "Access Documents folder",
  NSDownloadsFolderUsageDescription: "Access Downloads folder",
  NSNetworkVolumesUsageDescription: "Access network volumes",
  NSRemovableVolumesUsageDescription: "Access removable volumes",
  NSFileProviderPresenceUsageDescription:
    "Know when other apps access managed files",
  NSFileProviderDomainUsageDescription:
    "Access files managed by a file provider",
  NSHealthClinicalHealthRecordsShareUsageDescription:
    "Read clinical health records",
  NSHealthShareUsageDescription: "Read HealthKit data",
  NSHealthUpdateUsageDescription: "Write HealthKit data",
  NSHomeKitUsageDescription: "Access HomeKit configuration",
  NSLocationAlwaysAndWhenInUseUsageDescription: "Access location at all times",
  NSLocationUsageDescription: "Access location",
  NSLocationWhenInUseUsageDescription: "Access location while in foreground",
  NSLocationAlwaysUsageDescription: "Access location always (legacy)",
  NSAppleMusicUsageDescription: "Access media library",
  NSMotionUsageDescription: "Access accelerometer / motion data",
  NFCReaderUsageDescription: "Scan NFC tags",
  NSPhotoLibraryAddUsageDescription: "Add photos to photo library",
  NSPhotoLibraryUsageDescription: "Access photo library",
  NSAppleScriptEnabled: "AppleScript is enabled",
  NSAppleEventsUsageDescription: "Send Apple events",
  NSSystemAdministrationUsageDescription: "Manipulate system configuration",
  NSSiriUsageDescription: "Send data to Siri",
  NSSpeechRecognitionUsageDescription:
    "Send data to speech recognition servers",
  NSVideoSubscriberAccountUsageDescription: "Access TV provider account",
  UIRequiresPersistentWiFi: "Requires persistent Wi-Fi connection",
};

const ALL_PERMISSION_KEYS = Object.keys(PERMISSION_LABELS);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parsePlistInsights(value: Record<string, any>, t: TFunction) {
  const insights: Insight[] = [];

  // --- ATS analysis ---
  const ats = value.NSAppTransportSecurity as
    | Record<string, unknown>
    | undefined;
  if (ats) {
    if (ats.NSAllowsArbitraryLoads === true) {
      insights.push({
        id: "ats_arbitrary",
        severity: "high",
        title: t("plist_ats_arbitrary_title"),
        description: t("plist_ats_arbitrary_desc"),
      });
    } else {
      insights.push({
        id: "ats_arbitrary",
        severity: "ok",
        title: t("plist_ats_arbitrary_off_title"),
        description: t("plist_ats_arbitrary_off_desc"),
      });
    }

    if (ats.NSAllowsArbitraryLoadsForMedia === true) {
      insights.push({
        id: "ats_media",
        severity: "medium",
        title: t("plist_ats_media_title"),
        description: t("plist_ats_media_desc"),
      });
    }

    if (ats.NSAllowsArbitraryLoadsInWebContent === true) {
      insights.push({
        id: "ats_webcontent",
        severity: "medium",
        title: t("plist_ats_webcontent_title"),
        description: t("plist_ats_webcontent_desc"),
      });
    }

    if (ats.NSAllowsLocalNetworking === true) {
      insights.push({
        id: "ats_local",
        severity: "info",
        title: t("plist_ats_local_title"),
        description: t("plist_ats_local_desc"),
      });
    }

    if (ats.NSExceptionDomains) {
      const domains = Object.keys(
        ats.NSExceptionDomains as Record<string, unknown>,
      );
      insights.push({
        id: "ats_exceptions",
        severity: "info",
        title: t("plist_ats_exceptions_title", { count: domains.length }),
        description: t("plist_ats_exceptions_desc"),
        list: domains,
      });
    }
  } else {
    insights.push({
      id: "ats_default",
      severity: "ok",
      title: t("plist_ats_default_title"),
      description: t("plist_ats_default_desc"),
    });
  }

  // --- Encryption ---
  if (value.ITSAppUsesNonExemptEncryption === true) {
    insights.push({
      id: "encryption",
      severity: "info",
      title: t("plist_encryption_yes_title"),
      description: t("plist_encryption_yes_desc"),
    });
  } else if (value.ITSAppUsesNonExemptEncryption === false) {
    insights.push({
      id: "encryption",
      severity: "ok",
      title: t("plist_encryption_no_title"),
      description: t("plist_encryption_no_desc"),
    });
  } else {
    insights.push({
      id: "encryption",
      severity: "info",
      title: t("plist_encryption_missing_title"),
      description: t("plist_encryption_missing_desc"),
    });
  }

  // --- Permissions ---
  const permissions: PermissionEntry[] = [];
  for (const key of ALL_PERMISSION_KEYS) {
    if (key in value) {
      const usageDesc =
        typeof value[key] === "string" ? value[key] : String(value[key]);
      permissions.push({
        key,
        label: PERMISSION_LABELS[key],
        description: PERMISSION_DESCRIPTIONS[key],
        usageDescription: usageDesc,
        sensitive: SENSITIVE_PERMISSIONS.has(key),
      });
    }
  }

  const sensitiveCount = permissions.filter((p) => p.sensitive).length;
  if (sensitiveCount >= 5) {
    insights.push({
      id: "permissions",
      severity: "medium",
      title: t("plist_perms_excessive_title", { count: sensitiveCount }),
      description: t("plist_perms_excessive_desc", { count: sensitiveCount }),
    });
  } else if (sensitiveCount > 0) {
    insights.push({
      id: "permissions",
      severity: "info",
      title: t("plist_perms_some_title", { count: sensitiveCount }),
      description: t("plist_perms_some_desc", { count: sensitiveCount }),
    });
  } else if (permissions.length > 0) {
    insights.push({
      id: "permissions",
      severity: "ok",
      title: t("plist_perms_none_sensitive_title"),
      description: t("plist_perms_none_sensitive_desc", {
        count: permissions.length,
      }),
    });
  }

  // --- URL Schemes ---
  const urlTypes = value.CFBundleURLTypes as
    | Array<Record<string, unknown>>
    | undefined;
  const urlSchemes: URLSchemeEntry[] = [];
  if (urlTypes && Array.isArray(urlTypes)) {
    for (const entry of urlTypes) {
      urlSchemes.push({
        name: entry.CFBundleURLName as string | undefined,
        schemes: (entry.CFBundleURLSchemes as string[] | undefined) ?? [],
        role: entry.CFBundleTypeRole as string | undefined,
      });
    }
  }

  return { insights, permissions, urlSchemes };
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
    badge:
      "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    labelKey: "severity_medium",
  },
  info: {
    icon: Info,
    badge: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    labelKey: "severity_info",
  },
  ok: {
    icon: ShieldCheck,
    badge:
      "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
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
        <p className="text-xs text-muted-foreground leading-relaxed">
          {insight.description}
        </p>
        {insight.list && insight.list.length > 0 && (
          <ul className="mt-2 space-y-1">
            {insight.list.map((item, idx) => (
              <li
                key={idx}
                className="text-xs text-muted-foreground flex items-start gap-1.5"
              >
                <span className="text-muted-foreground/50 select-none">•</span>
                <span className="font-mono">{item}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function PermissionRow({ perm }: { perm: PermissionEntry }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-start gap-3 py-2.5 border-b last:border-b-0">
      <div className="mt-0.5 shrink-0">
        {perm.sensitive ? (
          <Unlock className="h-4 w-4 text-amber-500" />
        ) : (
          <Lock className="h-4 w-4 text-muted-foreground" />
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono font-medium">{perm.key}</span>
          {perm.sensitive && (
            <Badge
              variant="outline"
              className="text-[10px] px-1.5 py-0 border-amber-400 text-amber-600 dark:text-amber-400"
            >
              {t("plist_perm_sensitive")}
            </Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-0.5">
          {perm.label} — {perm.description}
        </p>
        {perm.usageDescription && (
          <p className="text-xs text-muted-foreground/70 mt-0.5 italic">
            "{perm.usageDescription}"
          </p>
        )}
      </div>
    </div>
  );
}

export function InfoPlistInsights({
  value,
  permsOpen,
  setPermsOpen,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  value: Record<string, any>;
  permsOpen: boolean;
  setPermsOpen: React.Dispatch<React.SetStateAction<boolean>>;
}) {
  const { t } = useTranslation();
  const { insights, permissions, urlSchemes } = parsePlistInsights(value, t);
  const [urlsOpen, setUrlsOpen] = useState(false);

  const highCount = insights.filter((i) => i.severity === "high").length;
  const mediumCount = insights.filter((i) => i.severity === "medium").length;
  const sensitivePerms = permissions.filter((p) => p.sensitive);

  return (
    <div className="h-full overflow-auto">
      <div className="p-4 max-w-3xl mx-auto space-y-6">
        {/* Summary bar */}
        <div className="flex items-center gap-4 rounded-lg border p-3 bg-muted/30">
          <div className="flex items-center gap-1.5 text-sm">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500 inline-block" />
            <span className="font-medium">{highCount}</span>
            <span className="text-muted-foreground">
              {t("manifest_summary_high")}
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500 inline-block" />
            <span className="font-medium">{mediumCount}</span>
            <span className="text-muted-foreground">
              {t("manifest_summary_medium")}
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <Unlock className="h-3.5 w-3.5 text-amber-500" />
            <span className="font-medium">{sensitivePerms.length}</span>
            <span className="text-muted-foreground">
              {t("plist_summary_sensitive_perms")}
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <Lock className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-medium">
              {permissions.length - sensitivePerms.length}
            </span>
            <span className="text-muted-foreground">
              {t("manifest_summary_normal_perms")}
            </span>
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
                ? t("plist_declared_permissions_count", {
                    count: permissions.length,
                  })
                : t("plist_declared_permissions")}
            </h2>
          </button>
          {permsOpen &&
            (permissions.length > 0 ? (
              <div className="rounded-lg border px-4 divide-y-0">
                {[...permissions]
                  .sort((a, b) => (b.sensitive ? 1 : 0) - (a.sensitive ? 1 : 0))
                  .map((perm) => (
                    <PermissionRow key={perm.key} perm={perm} />
                  ))}
              </div>
            ) : (
              <div className="rounded-lg border p-4 text-sm text-muted-foreground">
                {t("plist_no_permissions_desc")}
              </div>
            ))}
        </section>

        {/* URL Schemes */}
        {urlSchemes.length > 0 && (
          <section>
            <button
              className="flex items-center gap-1.5 w-full text-left mb-3 group"
              onClick={() => setUrlsOpen((o) => !o)}
            >
              <ChevronRight
                className={`h-4 w-4 text-muted-foreground transition-transform duration-150 ${urlsOpen ? "rotate-90" : ""}`}
              />
              <h2 className="text-sm font-semibold text-foreground group-hover:text-foreground/80">
                {t("plist_url_schemes_count", {
                  count: urlSchemes.reduce((n, u) => n + u.schemes.length, 0),
                })}
              </h2>
            </button>
            {urlsOpen && (
              <div className="rounded-lg border px-4 divide-y-0">
                {urlSchemes.map((entry, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-3 py-2.5 border-b last:border-b-0"
                  >
                    <div className="mt-0.5 shrink-0">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-medium">
                          {entry.schemes.map((s) => `${s}://`).join(", ")}
                        </span>
                        {entry.role && (
                          <Badge
                            variant="outline"
                            className="text-[10px] px-1.5 py-0"
                          >
                            {entry.role}
                          </Badge>
                        )}
                      </div>
                      {entry.name && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {entry.name}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  );
}
