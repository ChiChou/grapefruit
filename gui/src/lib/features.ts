import type React from "react";
import {
  FileText,
  FileCode,
  FileSearch,
  FolderOpen,
  FolderSearch,
  FolderKey,
  Cookie,
  Layout,
  Shield,
  Globe,
  Code,
  Settings,
  Network,
  Smartphone,
  KeyRound,
  Database,
  Cpu,
  Cable,
  Search,
  Info,
  Package,
  Braces,
  Link as LinkIcon,
  MapPin,
  Anchor,
  Blocks,
  Puzzle,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Archive,
  Lock,
} from "lucide-react";
import { SiFlutter, SiReact } from "@icons-pack/react-simple-icons";

import type { PlatformType, ModeType } from "@/context/SessionContext";

export type FeatureIcon = React.ComponentType<{ className?: string }>;

export interface RouteFeature {
  kind: "route";
  route: string;
  icon: FeatureIcon;
  label: string;
}

export interface PanelFeature {
  kind: "panel";
  id: string;
  component: string;
  icon: FeatureIcon;
  label: string;
  desc: string;
  params?: Record<string, string>;
}

type FeatureKey = `${PlatformType}:${ModeType}`;

const rf = (route: string, icon: FeatureIcon, label: string): RouteFeature => ({
  kind: "route",
  route,
  icon,
  label,
});

const pf = (
  id: string,
  component: string,
  icon: FeatureIcon,
  label: string,
  desc: string,
  params?: Record<string, string>,
): PanelFeature => ({
  kind: "panel",
  id,
  component,
  icon,
  label,
  desc,
  params,
});

const routeFeatures: Record<FeatureKey, RouteFeature[]> = {
  "fruity:app": [
    rf("general", Info, "general"),
    rf("modules", Package, "modules"),
    rf("classes", Braces, "classes"),
    rf("urls", LinkIcon, "URL Schemes"),
    rf("extensions", Blocks, "Extensions"),
    rf("hooks", Anchor, "hooks"),
    rf("device", Smartphone, "device_info"),
    rf("geolocation", MapPin, "geolocation_simulation"),
    rf("threads", Cpu, "Threads"),
  ],
  "fruity:daemon": [
    rf("modules", Package, "modules"),
    rf("classes", Braces, "classes"),
    rf("hooks", Anchor, "hooks"),
    rf("device", Smartphone, "device_info"),
    rf("threads", Cpu, "Threads"),
  ],
  "droid:app": [
    rf("general", Info, "general"),
    rf("components", Puzzle, "components"),
    rf("classes", Braces, "classes"),
    rf("urls", LinkIcon, "URL Schemes"),
    rf("hooks", Anchor, "hooks"),
    rf("modules", Package, "modules"),
    rf("device", Smartphone, "device_info"),
    rf("threads", Cpu, "Threads"),
  ],
  "droid:daemon": [
    rf("modules", Package, "modules"),
    rf("classes", Braces, "classes"),
    rf("threads", Cpu, "Threads"),
  ],
};

const panelFeatures: Record<FeatureKey, PanelFeature[]> = {
  "fruity:app": [
    pf("checksec_tab", "checksec", ShieldCheck, "mitigations", "home_checksec_desc"),
    pf("files_tab", "files", FolderSearch, "files", "home_files_desc", {
      path: "~",
    }),
    pf(
      "asset_catalog_tab",
      "assetCatalog",
      Layers,
      "Assets.car",
      "home_assetcatalog_desc",
    ),
    pf("handles_tab", "handles", FolderOpen, "lsof", "home_lsof_desc"),
    pf(
      "info_plist_tab",
      "infoPlist",
      FileText,
      "Info.plist",
      "home_infoplist_desc",
    ),
    pf(
      "info_plist_insights_tab",
      "infoPlistInsights",
      FileSearch,
      "plist_insights_title",
      "home_plist_insights_desc",
    ),
    pf(
      "binary_cookie_tab",
      "binaryCookie",
      Cookie,
      "Binary Cookies",
      "home_cookies_desc",
    ),
    pf(
      "userdefaults_tab",
      "userdefaults",
      Settings,
      "UserDefaults",
      "home_userdefaults_desc",
    ),
    pf(
      "entitlements_tab",
      "entitlements",
      Shield,
      "Entitlements",
      "home_entitlements_desc",
    ),
    pf("keychain_tab", "keychain", FolderKey, "KeyChain", "home_keychain_desc"),
    pf("ui_dump_tab", "uiDump", Layout, "inspect_ui", "home_ui_desc"),
    pf("webview_tab", "webview", Globe, "WebViews", "home_webview_desc"),
    pf("jsc_tab", "jsc", Code, "JSContext", "home_jsc_desc"),
    pf(
      "memory_scan_tab",
      "memoryScan",
      Search,
      "memory_scanner",
      "home_memory_scan_desc",
    ),
    pf("nsurl_tab", "nsurl", Network, "NSURL", "home_nsurl_desc"),
    pf(
      "flutter_channels_tab",
      "flutterChannels",
      SiFlutter,
      "flutter_channels",
      "flutter_channels_desc",
    ),
    pf("xpc_tab", "xpc", Cable, "XPC", "home_xpc_desc"),
    pf(
      "rn_tab",
      "reactNative",
      SiReact,
      "React Native",
      "RN bridge inspector, JS injection REPL",
    ),
    pf(
      "privacy_tab",
      "privacy",
      ShieldAlert,
      "privacy_monitor",
      "home_privacy_desc",
    ),
    pf("crypto_tab", "crypto", Lock, "crypto_monitor", "home_crypto_desc"),
  ],
  "fruity:daemon": [
    pf("checksec_tab", "checksec", ShieldCheck, "mitigations", "home_checksec_desc"),
    pf("files_tab", "files", FolderSearch, "files", "home_files_desc", {
      path: "/",
    }),
    pf("handles_tab", "handles", FolderOpen, "lsof", "home_lsof_desc"),
    pf(
      "memory_scan_tab",
      "memoryScan",
      Search,
      "memory_scanner",
      "home_memory_scan_desc",
    ),
    pf("nsurl_tab", "nsurl", Network, "NSURL", "home_nsurl_desc"),
    pf("xpc_tab", "xpc", Cable, "XPC", "home_xpc_desc"),
    pf(
      "privacy_tab",
      "privacy",
      ShieldAlert,
      "privacy_monitor",
      "home_privacy_desc",
    ),
  ],
  "droid:app": [
    pf("checksec_tab", "checksec", ShieldCheck, "mitigations", "home_checksec_desc"),
    pf("apk_browser_tab", "apkBrowser", Package, "apk_browser", "home_apk_browser_desc"),
    pf("files_tab", "files", FolderSearch, "files", "home_files_desc", {
      path: "/",
    }),
    pf(
      "droid_handles_tab",
      "droidHandles",
      FolderOpen,
      "lsof",
      "home_lsof_desc",
    ),
    pf(
      "droid_manifest_tab",
      "droidManifest",
      FileCode,
      "AndroidManifest.xml",
      "home_manifest_desc",
    ),
    pf("keystore_tab", "keystore", KeyRound, "keystore", "home_keystore_desc"),
    pf(
      "droid_providers_tab",
      "droidProviders",
      Database,
      "content_providers",
      "home_providers_desc",
    ),
    pf("jni_trace_tab", "jni", Cpu, "jni_trace", "home_jni_desc"),
    pf(
      "flutter_channels_tab",
      "flutterChannels",
      SiFlutter,
      "flutter_channels",
      "flutter_channels_desc",
    ),
    pf(
      "rn_tab",
      "reactNative",
      SiReact,
      "React Native",
      "RN bridge inspector, JS injection REPL",
    ),
    pf(
      "privacy_tab",
      "privacy",
      ShieldAlert,
      "privacy_monitor",
      "home_privacy_desc",
    ),
    pf("crypto_tab", "crypto", Lock, "crypto_monitor", "home_crypto_desc"),
    pf("droid_http_tab", "droidHttp", Network, "HTTP", "home_http_desc"),
    pf(
      "droid_resources_tab",
      "droidResources",
      Archive,
      "Resources",
      "Browse Android app resources",
    ),
    pf("droid_webview_tab", "droidWebview", Globe, "WebViews", "home_webview_desc"),
  ],
  "droid:daemon": [
    pf("checksec_tab", "checksec", ShieldCheck, "mitigations", "home_checksec_desc"),
    pf("files_tab", "files", FolderSearch, "files", "home_files_desc", {
      path: "/",
    }),
    pf(
      "droid_handles_tab",
      "droidHandles",
      FolderOpen,
      "lsof",
      "home_lsof_desc",
    ),
    pf(
      "memory_scan_tab",
      "memoryScan",
      Search,
      "memory_scanner",
      "home_memory_scan_desc",
    ),
    pf("jni_trace_tab", "jni", Cpu, "jni_trace", "home_jni_desc"),
  ],
};

export function getRouteFeatures(
  platform: PlatformType | undefined,
  mode: ModeType | undefined,
): RouteFeature[] {
  if (!platform || !mode) return [];
  return routeFeatures[`${platform}:${mode}`] ?? [];
}

export function getPanelFeatures(
  platform: PlatformType | undefined,
  mode: ModeType | undefined,
): PanelFeature[] {
  if (!platform || !mode) return [];
  return panelFeatures[`${platform}:${mode}`] ?? [];
}
