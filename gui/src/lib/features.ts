import type { LucideIcon } from "lucide-react";
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
} from "lucide-react";

import type { PlatformType, ModeType } from "@/context/SessionContext";

export interface RouteFeature {
  kind: "route";
  route: string;
  icon: LucideIcon;
  labelKey: string;
  labelFallback: string;
}

export interface PanelFeature {
  kind: "panel";
  id: string;
  component: string;
  icon: LucideIcon;
  labelKey: string;
  labelFallback: string;
  descKey: string;
  descFallback: string;
  params?: Record<string, string>;
}

type FeatureKey = `${PlatformType}:${ModeType}`;

const rf = (route: string, icon: LucideIcon, labelKey: string, labelFallback: string): RouteFeature =>
  ({ kind: "route", route, icon, labelKey, labelFallback });

const pf = (
  id: string, component: string, icon: LucideIcon,
  labelKey: string, labelFallback: string,
  descKey: string, descFallback: string,
  params?: Record<string, string>,
): PanelFeature =>
  ({ kind: "panel", id, component, icon, labelKey, labelFallback, descKey, descFallback, params });

// ── Route features (sidebar navigation) ──────────────────────────────

const routeFeatures: Record<FeatureKey, RouteFeature[]> = {
  "fruity:app": [
    rf("general", Info, "general", "General"),
    rf("modules", Package, "modules", "Modules"),
    rf("classes", Braces, "classes", "Classes"),
    rf("urls", LinkIcon, "", "URL Schemes"),
    rf("extensions", Blocks, "", "Extensions"),
    rf("hooks", Anchor, "hooks", "Hooks"),
    rf("device", Smartphone, "device_info", "Device Info"),
    rf("geolocation", MapPin, "geolocation_simulation", "Geolocation"),
  ],
  "fruity:daemon": [
    rf("modules", Package, "modules", "Modules"),
    rf("classes", Braces, "classes", "Classes"),
    rf("hooks", Anchor, "hooks", "Hooks"),
    rf("device", Smartphone, "device_info", "Device Info"),
  ],
  "droid:app": [
    rf("general", Info, "general", "General"),
    rf("components", Puzzle, "components", "Components"),
    rf("classes", Braces, "classes", "Classes"),
    rf("urls", LinkIcon, "", "URL Schemes"),
    rf("hooks", Anchor, "hooks", "Hooks"),
    rf("modules", Package, "modules", "Modules"),
    rf("device", Smartphone, "device_info", "Device Info"),
  ],
  "droid:daemon": [
    rf("modules", Package, "modules", "Modules"),
    rf("classes", Braces, "classes", "Classes"),
    rf("hooks", Anchor, "hooks", "Hooks"),
    rf("device", Smartphone, "device_info", "Device Info"),
  ],
};

// ── Panel features (dock panel launchers) ────────────────────────────

const panelFeatures: Record<FeatureKey, PanelFeature[]> = {
  "fruity:app": [
    pf("finder_tab", "finder", FolderSearch, "finder", "Finder", "home_finder_desc", "Browse the app sandbox file system", { path: "~" }),
    pf("handles_tab", "handles", FolderOpen, "", "lsof", "home_lsof_desc", "List open file handles"),
    pf("info_plist_tab", "infoPlist", FileText, "", "Info.plist", "home_infoplist_desc", "View Info.plist"),
    pf("info_plist_insights_tab", "infoPlistInsights", FileSearch, "plist_insights_title", "Plist Insights", "home_plist_insights_desc", "Analyze Info.plist"),
    pf("binary_cookie_tab", "binaryCookie", Cookie, "", "Binary Cookies", "home_cookies_desc", "View binary cookies"),
    pf("userdefaults_tab", "userdefaults", Settings, "", "UserDefaults", "home_userdefaults_desc", "View UserDefaults"),
    pf("entitlements_tab", "entitlements", Shield, "", "Entitlements", "home_entitlements_desc", "View entitlements"),
    pf("keychain_tab", "keychain", FolderKey, "", "KeyChain", "home_keychain_desc", "View keychain items"),
    pf("ui_dump_tab", "uiDump", Layout, "inspect_ui", "Inspect UI", "home_ui_desc", "Dump UI hierarchy"),
    pf("webview_tab", "webview", Globe, "", "WebViews", "home_webview_desc", "Inspect web views"),
    pf("jsc_tab", "jsc", Code, "", "JSContext", "home_jsc_desc", "JavaScriptCore REPL"),
    pf("memory_scan_tab", "memoryScan", Search, "memory_scanner", "Memory Scanner", "home_memory_scan_desc", "Scan process memory"),
    pf("nsurl_tab", "nsurl", Network, "", "NSURL", "home_nsurl_desc", "NSURL session tasks"),
    pf("flutter_channels_tab", "flutterChannels", Smartphone, "flutter_channels", "Flutter Channels", "flutter_channels_desc", "Flutter method channels"),
    pf("xpc_tab", "xpc", Cable, "", "XPC", "home_xpc_desc", "XPC communication"),
    pf("rn_tab", "reactNative", Smartphone, "", "React Native", "", "RN bridge inspector, JS injection REPL"),
  ],
  "fruity:daemon": [
    pf("finder_tab", "finder", FolderSearch, "finder", "Finder", "home_finder_desc", "Browse the file system", { path: "/" }),
    pf("handles_tab", "handles", FolderOpen, "", "lsof", "home_lsof_desc", "List open file handles"),
    pf("nsurl_tab", "nsurl", Network, "", "NSURL", "home_nsurl_desc", "NSURL session tasks"),
    pf("xpc_tab", "xpc", Cable, "", "XPC", "home_xpc_desc", "Trace XPC and NSXPC inter-process communication"),
  ],
  "droid:app": [
    pf("finder_tab", "finder", FolderSearch, "finder", "Finder", "home_finder_desc", "Browse the file system", { path: "/" }),
    pf("droid_handles_tab", "droidHandles", FolderOpen, "", "lsof", "home_lsof_desc", "List open file handles"),
    pf("droid_manifest_tab", "droidManifest", FileCode, "", "AndroidManifest.xml", "home_manifest_desc", "View Android manifest"),
    pf("keystore_tab", "keystore", KeyRound, "keystore", "Keystore", "home_keystore_desc", "View keystore"),
    pf("droid_providers_tab", "droidProviders", Database, "content_providers", "Content Providers", "home_providers_desc", "Content providers"),
    pf("jni_trace_tab", "jni", Cpu, "jni_trace", "JNI Trace", "home_jni_desc", "JNI tracing"),
    pf("flutter_channels_tab", "flutterChannels", Smartphone, "flutter_channels", "Flutter Channels", "flutter_channels_desc", "Flutter method channels"),
    pf("rn_tab", "reactNative", Smartphone, "", "React Native", "", "RN bridge inspector, JS injection REPL"),
  ],
  "droid:daemon": [
    pf("finder_tab", "finder", FolderSearch, "finder", "Finder", "home_finder_desc", "Browse the file system", { path: "/" }),
    pf("jni_trace_tab", "jni", Cpu, "jni_trace", "JNI Trace", "home_jni_desc", "JNI tracing"),
  ],
};

// ── Helpers ──────────────────────────────────────────────────────────

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
