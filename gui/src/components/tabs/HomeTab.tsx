import { useTranslation } from "react-i18next";
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
} from "lucide-react";

import logo from "@/assets/logo.svg";
import { useDock } from "@/context/DockContext";
import { useSession, Platform, Mode } from "@/context/SessionContext";

interface FeatureItem {
  icon: React.ReactNode;
  id: string;
  component: string;
  title: string;
  desc: string;
  params?: Record<string, string>;
}

function LauncherItem({
  icon,
  id,
  component,
  title,
  desc,
  params,
}: FeatureItem) {
  const { openSingletonPanel } = useDock();

  return (
    <button
      type="button"
      onClick={() => openSingletonPanel({ id, component, title, params })}
      className="flex items-center gap-3 p-3 rounded-lg hover:bg-accent transition-colors text-left"
    >
      <div className="w-12 h-12 shrink-0 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
        {icon}
      </div>
      <div className="min-w-0">
        <h3 className="font-medium text-base">{title}</h3>
        <p className="text-sm text-muted-foreground truncate">{desc}</p>
      </div>
    </button>
  );
}

export function HomeTab() {
  const { t } = useTranslation();
  const { platform, mode } = useSession();

  const isFruityApp = platform === Platform.Fruity && mode === Mode.App;
  const isFruityDaemon = platform === Platform.Fruity && mode === Mode.Daemon;
  const isDroidApp = platform === Platform.Droid && mode === Mode.App;

  const fruityAppFeatures: FeatureItem[] = [
    {
      icon: <FolderSearch className="w-6 h-6" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("home_finder_desc"),
      params: { path: "~" },
    },
    {
      icon: <FolderOpen className="w-6 h-6" />,
      id: "handles_tab",
      component: "handles",
      title: "lsof",
      desc: t("home_lsof_desc"),
    },
    {
      icon: <FileText className="w-6 h-6" />,
      id: "info_plist_tab",
      component: "infoPlist",
      title: "Info.plist",
      desc: t("home_infoplist_desc"),
    },
    {
      icon: <FileSearch className="w-6 h-6" />,
      id: "info_plist_insights_tab",
      component: "infoPlistInsights",
      title: t("plist_insights_title"),
      desc: t("home_plist_insights_desc"),
    },
    {
      icon: <Cookie className="w-6 h-6" />,
      id: "binary_cookie_tab",
      component: "binaryCookie",
      title: "Binary Cookies",
      desc: t("home_cookies_desc"),
    },
    {
      icon: <Settings className="w-6 h-6" />,
      id: "userdefaults_tab",
      component: "userdefaults",
      title: "UserDefaults",
      desc: t("home_userdefaults_desc"),
    },
    {
      icon: <Shield className="w-6 h-6" />,
      id: "entitlements_tab",
      component: "entitlements",
      title: "Entitlements",
      desc: t("home_entitlements_desc"),
    },
    {
      icon: <FolderKey className="w-6 h-6" />,
      id: "keychain_tab",
      component: "keychain",
      title: "KeyChain",
      desc: t("home_keychain_desc"),
    },
    {
      icon: <Layout className="w-6 h-6" />,
      id: "ui_dump_tab",
      component: "uiDump",
      title: t("inspect_ui"),
      desc: t("home_ui_desc"),
    },
    {
      icon: <Globe className="w-6 h-6" />,
      id: "webview_tab",
      component: "webview",
      title: "WebViews",
      desc: t("home_webview_desc"),
    },
    {
      icon: <Code className="w-6 h-6" />,
      id: "jsc_tab",
      component: "jsc",
      title: "JSContext",
      desc: t("home_jsc_desc"),
    },
    {
      icon: <Search className="w-6 h-6" />,
      id: "memory_scan_tab",
      component: "memoryScan",
      title: t("memory_scanner"),
      desc: t("home_memory_scan_desc"),
    },
    {
      icon: <Network className="w-6 h-6" />,
      id: "nsurl_tab",
      component: "nsurl",
      title: "NSURL",
      desc: t("home_nsurl_desc"),
    },
    {
      icon: <Smartphone className="w-6 h-6" />,
      id: "flutter_channels_tab",
      component: "flutterChannels",
      title: t("flutter_channels"),
      desc: t("flutter_channels_desc"),
    },
    {
      icon: <Cable className="w-6 h-6" />,
      id: "xpc_tab",
      component: "xpc",
      title: "XPC",
      desc: t("home_xpc_desc"),
    },
    {
      icon: <Smartphone className="w-6 h-6" />,
      id: "rn_tab",
      component: "reactNative",
      title: "React Native",
      desc: "RN bridge inspector, JS injection REPL",
    },
  ];

  const fruityDaemonFeatures: FeatureItem[] = [
    {
      icon: <FolderSearch className="w-6 h-6" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("home_finder_desc"),
      params: { path: "/" },
    },
    {
      icon: <FolderOpen className="w-6 h-6" />,
      id: "handles_tab",
      component: "handles",
      title: "lsof",
      desc: t("home_lsof_desc"),
    },
    {
      icon: <Network className="w-6 h-6" />,
      id: "nsurl_tab",
      component: "nsurl",
      title: "NSURL",
      desc: t("home_nsurl_desc"),
    },
    {
      icon: <Cable className="w-6 h-6" />,
      id: "xpc_tab",
      component: "xpc",
      title: "XPC",
      desc: "Trace XPC and NSXPC inter-process communication",
    },
  ];

  const droidAppFeatures: FeatureItem[] = [
    {
      icon: <FolderSearch className="w-6 h-6" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("home_finder_desc"),
      params: { path: "/" },
    },
    {
      icon: <FolderOpen className="w-6 h-6" />,
      id: "droid_handles_tab",
      component: "droidHandles",
      title: "lsof",
      desc: t("home_lsof_desc"),
    },
    {
      icon: <FileCode className="w-6 h-6" />,
      id: "droid_manifest_tab",
      component: "droidManifest",
      title: "AndroidManifest.xml",
      desc: t("home_manifest_desc"),
    },
    {
      icon: <KeyRound className="w-6 h-6" />,
      id: "keystore_tab",
      component: "keystore",
      title: t("keystore"),
      desc: t("home_keystore_desc"),
    },
    {
      icon: <Database className="w-6 h-6" />,
      id: "droid_providers_tab",
      component: "droidProviders",
      title: t("content_providers"),
      desc: t("home_providers_desc"),
    },
    {
      icon: <Cpu className="w-6 h-6" />,
      id: "jni_trace_tab",
      component: "jni",
      title: t("jni_trace"),
      desc: t("home_jni_desc"),
    },
    {
      icon: <Smartphone className="w-6 h-6" />,
      id: "flutter_channels_tab",
      component: "flutterChannels",
      title: t("flutter_channels"),
      desc: t("flutter_channels_desc"),
    },
    {
      icon: <Smartphone className="w-6 h-6" />,
      id: "rn_tab",
      component: "reactNative",
      title: "React Native",
      desc: "RN bridge inspector, JS injection REPL",
    },
  ];

  const droidDaemonFeatures: FeatureItem[] = [
    {
      icon: <FolderSearch className="w-6 h-6" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("home_finder_desc"),
      params: { path: "/" },
    },
    {
      icon: <Cpu className="w-6 h-6" />,
      id: "jni_trace_tab",
      component: "jni",
      title: t("jni_trace"),
      desc: t("home_jni_desc"),
    },
  ];

  const features = isFruityApp
    ? fruityAppFeatures
    : isFruityDaemon
      ? fruityDaemonFeatures
      : isDroidApp
        ? droidAppFeatures
        : droidDaemonFeatures;

  return (
    <div className="h-full flex flex-col items-center p-8 overflow-auto">
      <div className="max-w-5xl w-full space-y-6">
        <div className="flex justify-center">
          <img src={logo} alt="logo" className="h-10 w-40" />
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-1">
          {features.map((feature) => (
            <LauncherItem key={feature.id} {...feature} />
          ))}
        </div>
      </div>
    </div>
  );
}
