import { useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  ChevronRight,
  Fingerprint,
  Globe,
  Eye,
  Link2,
  Loader2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useFruityQuery } from "@/lib/queries";

// ── Apple Required-Reason API labels ─────────────────────────────────

const API_TYPE_LABELS: Record<string, string> = {
  "NSPrivacyAccessedAPICategoryFileTimestamp": "File Timestamp",
  "NSPrivacyAccessedAPICategorySystemBootTime": "System Boot Time",
  "NSPrivacyAccessedAPICategoryDiskSpace": "Disk Space",
  "NSPrivacyAccessedAPICategoryActiveKeyboards": "Active Keyboards",
  "NSPrivacyAccessedAPICategoryUserDefaults": "UserDefaults",
};

const REASON_LABELS: Record<string, string> = {
  "DDA9.1": "Display to user",
  "C617.1": "Timestamps in documents",
  "3B52.1": "File management / document picking",
  "0A2A.1": "Third-party SDK wrapper",
  "35F9.1": "System boot time for measuring elapsed time",
  "8FFB.1": "Determine available disk space",
  "E174.1": "Write or check downloaded file",
  "85F4.1": "Disk space health check",
  "AB6B.1": "Detect low disk space",
  "7D9E.1": "Downloaded file management",
  "B728.1": "Display text with correct keyboards",
  "54BD.1": "Customize UI for keyboards",
  "CA92.1": "Store preferences / state",
  "1C8F.1": "Third-party SDK wrapper",
  "C56D.1": "Third-party SDK wrapper",
};

const DATA_TYPE_LABELS: Record<string, string> = {
  NSPrivacyCollectedDataTypeName: "Name",
  NSPrivacyCollectedDataTypeEmailAddress: "Email Address",
  NSPrivacyCollectedDataTypePhoneNumber: "Phone Number",
  NSPrivacyCollectedDataTypePhysicalAddress: "Physical Address",
  NSPrivacyCollectedDataTypeOtherUserContactInfo: "Other Contact Info",
  NSPrivacyCollectedDataTypeHealth: "Health",
  NSPrivacyCollectedDataTypeFitness: "Fitness",
  NSPrivacyCollectedDataTypePaymentInfo: "Payment Info",
  NSPrivacyCollectedDataTypeCreditInfo: "Credit Info",
  NSPrivacyCollectedDataTypeOtherFinancialInfo: "Other Financial Info",
  NSPrivacyCollectedDataTypePreciseLocation: "Precise Location",
  NSPrivacyCollectedDataTypeCoarseLocation: "Coarse Location",
  NSPrivacyCollectedDataTypeSensitiveInfo: "Sensitive Info",
  NSPrivacyCollectedDataTypeContacts: "Contacts",
  NSPrivacyCollectedDataTypeEmailsOrTextMessages: "Emails / Text Messages",
  NSPrivacyCollectedDataTypePhotosorVideos: "Photos or Videos",
  NSPrivacyCollectedDataTypeAudioData: "Audio Data",
  NSPrivacyCollectedDataTypeGameplayContent: "Gameplay Content",
  NSPrivacyCollectedDataTypeCustomerSupport: "Customer Support",
  NSPrivacyCollectedDataTypeOtherUserContent: "Other User Content",
  NSPrivacyCollectedDataTypeBrowsingHistory: "Browsing History",
  NSPrivacyCollectedDataTypeSearchHistory: "Search History",
  NSPrivacyCollectedDataTypeUserID: "User ID",
  NSPrivacyCollectedDataTypeDeviceID: "Device ID",
  NSPrivacyCollectedDataTypePurchaseHistory: "Purchase History",
  NSPrivacyCollectedDataTypeProductInteraction: "Product Interaction",
  NSPrivacyCollectedDataTypeAdvertisingData: "Advertising Data",
  NSPrivacyCollectedDataTypeOtherUsageData: "Other Usage Data",
  NSPrivacyCollectedDataTypeCrashData: "Crash Data",
  NSPrivacyCollectedDataTypePerformanceData: "Performance Data",
  NSPrivacyCollectedDataTypeOtherDiagnosticData: "Other Diagnostic Data",
  NSPrivacyCollectedDataTypeEnvironmentScanning: "Environment Scanning",
  NSPrivacyCollectedDataTypeHands: "Hands",
  NSPrivacyCollectedDataTypeHead: "Head",
  NSPrivacyCollectedDataTypeOtherDataTypes: "Other Data Types",
};

const PURPOSE_LABELS: Record<string, string> = {
  NSPrivacyCollectedDataTypePurposeThirdPartyAdvertising: "Third-Party Advertising",
  NSPrivacyCollectedDataTypePurposeDeveloperAdvertising: "Developer Advertising",
  NSPrivacyCollectedDataTypePurposeAnalytics: "Analytics",
  NSPrivacyCollectedDataTypePurposeProductPersonalization: "Product Personalization",
  NSPrivacyCollectedDataTypePurposeAppFunctionality: "App Functionality",
  NSPrivacyCollectedDataTypePurposeOther: "Other",
};

// ── Severity system (matching InfoPlistInsights) ─────────────────────

type Severity = "high" | "medium" | "info" | "ok";

const SEVERITY_CONFIG: Record<
  Severity,
  { icon: React.ComponentType<{ className?: string }>; badge: string; label: string }
> = {
  high: {
    icon: ShieldAlert,
    badge: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    label: "High",
  },
  medium: {
    icon: AlertTriangle,
    badge: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    label: "Medium",
  },
  info: {
    icon: Info,
    badge: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    label: "Info",
  },
  ok: {
    icon: ShieldCheck,
    badge: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    label: "OK",
  },
};

// ── Parsing ──────────────────────────────────────────────────────────

interface Insight {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  list?: string[];
}

interface AccessedAPI {
  apiType: string;
  apiTypeLabel: string;
  reasons: { code: string; label: string }[];
}

interface CollectedData {
  dataType: string;
  dataTypeLabel: string;
  linkedToUser: boolean;
  usedForTracking: boolean;
  purposes: string[];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseXCPrivacy(value: Record<string, any>) {
  const insights: Insight[] = [];

  // Tracking
  const isTracking = value.NSPrivacyTracking as boolean | undefined;
  if (isTracking === true) {
    insights.push({
      id: "tracking",
      severity: "high",
      title: "App declares data tracking",
      description:
        "NSPrivacyTracking is true — the app declares it tracks users across apps/websites for advertising or data broker purposes.",
    });
  } else {
    insights.push({
      id: "tracking",
      severity: "ok",
      title: "App does not declare tracking",
      description:
        "NSPrivacyTracking is false or absent — the app does not declare cross-app/website tracking.",
    });
  }

  // Tracking domains
  const trackingDomains = value.NSPrivacyTrackingDomains as string[] | undefined;
  if (trackingDomains && trackingDomains.length > 0) {
    insights.push({
      id: "tracking_domains",
      severity: "medium",
      title: `${trackingDomains.length} tracking domain${trackingDomains.length !== 1 ? "s" : ""} declared`,
      description:
        "These domains are blocked when the user opts out of tracking via App Tracking Transparency.",
      list: trackingDomains,
    });
  }

  // Accessed APIs
  const rawAPIs = value.NSPrivacyAccessedAPITypes as
    | Array<Record<string, unknown>>
    | undefined;
  const accessedAPIs: AccessedAPI[] = [];
  if (rawAPIs && rawAPIs.length > 0) {
    for (const entry of rawAPIs) {
      const apiType = (entry.NSPrivacyAccessedAPIType as string) || "unknown";
      const rawReasons = (entry.NSPrivacyAccessedAPITypeReasons as string[]) || [];
      accessedAPIs.push({
        apiType,
        apiTypeLabel: API_TYPE_LABELS[apiType] || apiType.replace("NSPrivacyAccessedAPICategory", ""),
        reasons: rawReasons.map((r) => ({
          code: r,
          label: REASON_LABELS[r] || r,
        })),
      });
    }
    insights.push({
      id: "accessed_apis",
      severity: "info",
      title: `${accessedAPIs.length} required-reason API${accessedAPIs.length !== 1 ? "s" : ""} declared`,
      description:
        "These APIs require a declared reason under Apple's Required Reason API policy.",
    });
  } else {
    insights.push({
      id: "accessed_apis",
      severity: "ok",
      title: "No required-reason APIs declared",
      description: "The manifest does not list any required-reason API usage.",
    });
  }

  // Collected data
  const rawData = value.NSPrivacyCollectedDataTypes as
    | Array<Record<string, unknown>>
    | undefined;
  const collectedData: CollectedData[] = [];
  if (rawData && rawData.length > 0) {
    for (const entry of rawData) {
      const dataType = (entry.NSPrivacyCollectedDataType as string) || "unknown";
      collectedData.push({
        dataType,
        dataTypeLabel: DATA_TYPE_LABELS[dataType] || dataType.replace("NSPrivacyCollectedDataType", ""),
        linkedToUser: entry.NSPrivacyCollectedDataTypeLinked === true,
        usedForTracking: entry.NSPrivacyCollectedDataTypeTracking === true,
        purposes: ((entry.NSPrivacyCollectedDataTypePurposes as string[]) || []).map(
          (p) => PURPOSE_LABELS[p] || p.replace("NSPrivacyCollectedDataTypePurpose", ""),
        ),
      });
    }

    const trackingCount = collectedData.filter((d) => d.usedForTracking).length;
    const linkedCount = collectedData.filter((d) => d.linkedToUser).length;

    if (trackingCount > 0) {
      insights.push({
        id: "data_tracking",
        severity: "high",
        title: `${trackingCount} data type${trackingCount !== 1 ? "s" : ""} used for tracking`,
        description: "These collected data types are declared as being used for tracking purposes.",
        list: collectedData.filter((d) => d.usedForTracking).map((d) => d.dataTypeLabel),
      });
    }

    if (linkedCount > 0) {
      insights.push({
        id: "data_linked",
        severity: "medium",
        title: `${linkedCount} data type${linkedCount !== 1 ? "s" : ""} linked to user identity`,
        description: "These collected data types are linked to the user's identity.",
        list: collectedData.filter((d) => d.linkedToUser).map((d) => d.dataTypeLabel),
      });
    }

    insights.push({
      id: "data_collected",
      severity: collectedData.length >= 10 ? "medium" : "info",
      title: `${collectedData.length} data type${collectedData.length !== 1 ? "s" : ""} collected`,
      description: "Total data types declared in the privacy nutrition label.",
    });
  } else {
    insights.push({
      id: "data_collected",
      severity: "ok",
      title: "No collected data types declared",
      description: "The manifest does not declare any collected data types.",
    });
  }

  return { insights, accessedAPIs, collectedData };
}

// ── Subcomponents ────────────────────────────────────────────────────

function InsightCard({ insight }: { insight: Insight }) {
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
            {cfg.label}
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

// ── Main component ───────────────────────────────────────────────────

export interface XCPrivacyTabParams {
  path: string;
}

export function XCPrivacyTab({
  params,
}: IDockviewPanelProps<XCPrivacyTabParams>) {
  const fullPath = params?.path || "";

  const { data, isLoading, error } = useFruityQuery(
    ["xcprivacy", fullPath],
    (api) => api.fs.plist(fullPath),
    { enabled: !!fullPath },
  );

  const [apisOpen, setApisOpen] = useState(false);
  const [dataOpen, setDataOpen] = useState(false);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {(error as Error).message}
      </div>
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const value = (data?.value as Record<string, any>) ?? null;
  if (!value) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No content
      </div>
    );
  }

  const { insights, accessedAPIs, collectedData } = parseXCPrivacy(value);
  const highCount = insights.filter((i) => i.severity === "high").length;
  const mediumCount = insights.filter((i) => i.severity === "medium").length;

  return (
    <div className="h-full overflow-auto">
      <div className="p-4 max-w-3xl mx-auto space-y-6">
        {/* Summary bar */}
        <div className="flex items-center gap-4 rounded-lg border p-3 bg-muted/30">
          <div className="flex items-center gap-1.5 text-sm">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500 inline-block" />
            <span className="font-medium">{highCount}</span>
            <span className="text-muted-foreground">High</span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500 inline-block" />
            <span className="font-medium">{mediumCount}</span>
            <span className="text-muted-foreground">Medium</span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <Fingerprint className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-medium">{collectedData.length}</span>
            <span className="text-muted-foreground">Data Types</span>
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <Eye className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-medium">{accessedAPIs.length}</span>
            <span className="text-muted-foreground">APIs</span>
          </div>
        </div>

        {/* Findings */}
        <section>
          <h2 className="text-sm font-semibold mb-3 text-foreground">
            Privacy Findings
          </h2>
          <div className="space-y-2">
            {insights.map((insight) => (
              <InsightCard key={insight.id} insight={insight} />
            ))}
          </div>
        </section>

        {/* Required Reason APIs */}
        {accessedAPIs.length > 0 && (
          <section>
            <button
              className="flex items-center gap-1.5 w-full text-left mb-3 group"
              onClick={() => setApisOpen((o) => !o)}
            >
              <ChevronRight
                className={`h-4 w-4 text-muted-foreground transition-transform duration-150 ${apisOpen ? "rotate-90" : ""}`}
              />
              <h2 className="text-sm font-semibold text-foreground group-hover:text-foreground/80">
                Required Reason APIs ({accessedAPIs.length})
              </h2>
            </button>
            {apisOpen && (
              <div className="rounded-lg border px-4 divide-y-0">
                {accessedAPIs.map((api) => (
                  <div
                    key={api.apiType}
                    className="flex items-start gap-3 py-2.5 border-b last:border-b-0"
                  >
                    <div className="mt-0.5 shrink-0">
                      <Link2 className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-medium">
                          {api.apiTypeLabel}
                        </span>
                        <Badge
                          variant="outline"
                          className="text-[10px] px-1.5 py-0"
                        >
                          {api.reasons.length} reason{api.reasons.length !== 1 ? "s" : ""}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground/70 font-mono mt-0.5">
                        {api.apiType}
                      </p>
                      <ul className="mt-1.5 space-y-0.5">
                        {api.reasons.map((r) => (
                          <li
                            key={r.code}
                            className="text-xs text-muted-foreground flex items-start gap-1.5"
                          >
                            <span className="text-muted-foreground/50 select-none">•</span>
                            <span>
                              <span className="font-mono">{r.code}</span>
                              {" — "}
                              {r.label}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* Collected Data Types */}
        {collectedData.length > 0 && (
          <section>
            <button
              className="flex items-center gap-1.5 w-full text-left mb-3 group"
              onClick={() => setDataOpen((o) => !o)}
            >
              <ChevronRight
                className={`h-4 w-4 text-muted-foreground transition-transform duration-150 ${dataOpen ? "rotate-90" : ""}`}
              />
              <h2 className="text-sm font-semibold text-foreground group-hover:text-foreground/80">
                Collected Data Types ({collectedData.length})
              </h2>
            </button>
            {dataOpen && (
              <div className="rounded-lg border px-4 divide-y-0">
                {collectedData.map((d) => (
                  <div
                    key={d.dataType}
                    className="flex items-start gap-3 py-2.5 border-b last:border-b-0"
                  >
                    <div className="mt-0.5 shrink-0">
                      {d.usedForTracking ? (
                        <Globe className="h-4 w-4 text-red-500" />
                      ) : d.linkedToUser ? (
                        <Fingerprint className="h-4 w-4 text-amber-500" />
                      ) : (
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-medium">
                          {d.dataTypeLabel}
                        </span>
                        {d.usedForTracking && (
                          <Badge
                            variant="outline"
                            className="text-[10px] px-1.5 py-0 border-red-400 text-red-600 dark:text-red-400"
                          >
                            Tracking
                          </Badge>
                        )}
                        {d.linkedToUser && (
                          <Badge
                            variant="outline"
                            className="text-[10px] px-1.5 py-0 border-amber-400 text-amber-600 dark:text-amber-400"
                          >
                            Linked to User
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground/70 font-mono mt-0.5">
                        {d.dataType}
                      </p>
                      {d.purposes.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Purposes: {d.purposes.join(", ")}
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
