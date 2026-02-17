import { useTranslation } from "react-i18next";
import {
  FileText,
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
} from "lucide-react";

import logo from "@/assets/logo.svg";
import { useDock } from "@/context/DockContext";
import { useSession, Platform, Mode } from "@/context/SessionContext";

interface FeatureCardProps {
  icon: React.ReactNode;
  id: string;
  component: string;
  title: string;
  desc: string;
  params?: Record<string, string>;
}

function FeatureCard({
  icon,
  id,
  component,
  title,
  desc,
  params,
}: FeatureCardProps) {
  const { openSingletonPanel } = useDock();

  return (
    <button
      type="button"
      onClick={() => openSingletonPanel({ id, component, title, params })}
      className="flex items-center gap-3 p-3 rounded-lg border border-border bg-card hover:bg-accent transition-colors text-left"
    >
      <div className="w-9 h-9 shrink-0 rounded-full bg-primary/10 flex items-center justify-center text-primary">
        {icon}
      </div>
      <div className="min-w-0">
        <h3 className="font-medium text-sm">{title}</h3>
        <p className="text-xs text-muted-foreground">{desc}</p>
      </div>
    </button>
  );
}

export function QuickStartTab() {
  const { t } = useTranslation();
  const { platform, mode } = useSession();

  const isFruityApp = platform === Platform.Fruity && mode === Mode.App;
  const isFruityDaemon = platform === Platform.Fruity && mode === Mode.Daemon;
  const isDroidApp = platform === Platform.Droid && mode === Mode.App;

  const fruityAppFeatures: FeatureCardProps[] = [
    {
      icon: <FolderSearch className="w-5 h-5" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("quickstart_finder_desc"),
      params: { path: "~" },
    },
    {
      icon: <FolderOpen className="w-5 h-5" />,
      id: "handles_tab",
      component: "handles",
      title: "lsof",
      desc: t("quickstart_lsof_desc"),
    },
    {
      icon: <FileText className="w-5 h-5" />,
      id: "info_plist_tab",
      component: "infoPlist",
      title: "Info.plist",
      desc: t("quickstart_infoplist_desc"),
    },
    {
      icon: <Shield className="w-5 h-5" />,
      id: "entitlements_tab",
      component: "entitlements",
      title: "Entitlements",
      desc: t("quickstart_entitlements_desc"),
    },
    {
      icon: <Cookie className="w-5 h-5" />,
      id: "binary_cookie_tab",
      component: "binaryCookie",
      title: "Binary Cookies",
      desc: t("quickstart_cookies_desc"),
    },
    {
      icon: <FolderKey className="w-5 h-5" />,
      id: "keychain_tab",
      component: "keychain",
      title: "KeyChain",
      desc: t("quickstart_keychain_desc"),
    },
    {
      icon: <Settings className="w-5 h-5" />,
      id: "userdefaults_tab",
      component: "userdefaults",
      title: "UserDefaults",
      desc: t("quickstart_userdefaults_desc"),
    },
    {
      icon: <Layout className="w-5 h-5" />,
      id: "ui_dump_tab",
      component: "uiDump",
      title: t("inspect_ui"),
      desc: t("quickstart_ui_desc"),
    },
    {
      icon: <Globe className="w-5 h-5" />,
      id: "webview_tab",
      component: "webview",
      title: "WebViews",
      desc: t("quickstart_webview_desc"),
    },
    {
      icon: <Code className="w-5 h-5" />,
      id: "jsc_tab",
      component: "jsc",
      title: "JSContext",
      desc: t("quickstart_jsc_desc"),
    },
    {
      icon: <Network className="w-5 h-5" />,
      id: "http_log_tab",
      component: "httpLog",
      title: "HTTP Log",
      desc: t("quickstart_httplog_desc"),
    },
    {
      icon: <Smartphone className="w-5 h-5" />,
      id: "flutter_channels_tab",
      component: "flutterChannels",
      title: t("flutter_channels"),
      desc: t("flutter_channels_desc"),
    },
  ];

  const fruityDaemonFeatures: FeatureCardProps[] = [
    {
      icon: <FolderSearch className="w-5 h-5" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("quickstart_finder_desc"),
      params: { path: "/" },
    },
    {
      icon: <FolderOpen className="w-5 h-5" />,
      id: "handles_tab",
      component: "handles",
      title: "lsof",
      desc: t("quickstart_lsof_desc"),
    },
    {
      icon: <Network className="w-5 h-5" />,
      id: "http_log_tab",
      component: "httpLog",
      title: "HTTP Log",
      desc: t("quickstart_httplog_desc"),
    },
  ];

  const droidAppFeatures: FeatureCardProps[] = [
    {
      icon: <FolderSearch className="w-5 h-5" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("quickstart_finder_desc"),
      params: { path: "/" },
    },
    {
      icon: <KeyRound className="w-5 h-5" />,
      id: "keystore_tab",
      component: "keystore",
      title: t("keystore"),
      desc: t("quickstart_keystore_desc"),
    },
    {
      icon: <Smartphone className="w-5 h-5" />,
      id: "flutter_channels_tab",
      component: "flutterChannels",
      title: t("flutter_channels"),
      desc: t("flutter_channels_desc"),
    },
  ];

  const droidDaemonFeatures: FeatureCardProps[] = [
    {
      icon: <FolderSearch className="w-5 h-5" />,
      id: "finder_tab",
      component: "finder",
      title: t("finder"),
      desc: t("quickstart_finder_desc"),
      params: { path: "/" },
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
    <div className="h-full flex flex-col items-center justify-center p-8 overflow-auto">
      <div className="max-w-2xl w-full space-y-6">
        <div className="flex justify-center">
          <img src={logo} alt="logo" className="h-10 w-40" />
        </div>
        <div className="grid grid-cols-2 gap-2">
          {features.map((feature) => (
            <FeatureCard key={feature.id} {...feature} />
          ))}
        </div>
      </div>
    </div>
  );
}
