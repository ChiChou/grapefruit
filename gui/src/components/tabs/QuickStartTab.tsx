import { useTranslation } from "react-i18next";
import {
  FileText,
  FolderOpen,
  FolderKey,
  Cookie,
  Layout,
  Shield,
  Globe,
  Code,
  Settings,
  Network,
} from "lucide-react";

import { useDock } from "@/context/DockContext";
import { useSession, Platform } from "@/context/SessionContext";

interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  onClick: () => void;
}

function FeatureCard({ icon, title, description, onClick }: FeatureCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col items-center p-4 rounded-lg border border-border bg-card hover:bg-accent transition-colors text-center"
    >
      <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center mb-3 text-primary">
        {icon}
      </div>
      <h3 className="font-medium text-sm mb-1">{title}</h3>
      <p className="text-xs text-muted-foreground">{description}</p>
    </button>
  );
}

export function QuickStartTab() {
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();
  const { platform } = useSession();

  const openHandlesTab = () => {
    openSingletonPanel({
      id: "handles_tab",
      component: "handles",
      title: "lsof",
    });
  };

  const openInfoPlistTab = () => {
    openSingletonPanel({
      id: "info_plist_tab",
      component: "infoPlist",
      title: "Info.plist",
    });
  };

  const openBinaryCookieTab = () => {
    openSingletonPanel({
      id: "binary_cookie_tab",
      component: "binaryCookie",
      title: "Binary Cookies",
    });
  };

  const openKeyChainTab = () => {
    openSingletonPanel({
      id: "keychain_tab",
      component: "keychain",
      title: "KeyChain",
    });
  };

  const openUIDumpTab = () => {
    openSingletonPanel({
      id: "ui_dump_tab",
      component: "uiDump",
      title: t("inspect_ui"),
    });
  };

  const openEntitlementsTab = () => {
    openSingletonPanel({
      id: "entitlements_tab",
      component: "entitlements",
      title: "Entitlements",
    });
  };

  const openWebViewTab = () => {
    openSingletonPanel({
      id: "webview_tab",
      component: "webview",
      title: "WebViews",
    });
  };

  const openJSCTab = () => {
    openSingletonPanel({
      id: "jsc_tab",
      component: "jsc",
      title: "JSContext",
    });
  };

  const openUserDefaultsTab = () => {
    openSingletonPanel({
      id: "userdefaults_tab",
      component: "userdefaults",
      title: "UserDefaults",
    });
  };

  const openHttpLogTab = () => {
    openSingletonPanel({
      id: "http_log_tab",
      component: "httpLog",
      title: "HTTP Log",
    });
  };

  const features = [
    {
      icon: <FolderOpen className="w-5 h-5" />,
      title: "lsof",
      description: t("quickstart_lsof_desc"),
      onClick: openHandlesTab,
    },
    {
      icon: <FileText className="w-5 h-5" />,
      title: "Info.plist",
      description: t("quickstart_infoplist_desc"),
      onClick: openInfoPlistTab,
    },
    {
      icon: <Shield className="w-5 h-5" />,
      title: "Entitlements",
      description: t("quickstart_entitlements_desc"),
      onClick: openEntitlementsTab,
    },
    {
      icon: <Cookie className="w-5 h-5" />,
      title: "Binary Cookies",
      description: t("quickstart_cookies_desc"),
      onClick: openBinaryCookieTab,
    },
    {
      icon: <FolderKey className="w-5 h-5" />,
      title: "KeyChain",
      description: t("quickstart_keychain_desc"),
      onClick: openKeyChainTab,
    },
    {
      icon: <Settings className="w-5 h-5" />,
      title: "UserDefaults",
      description: t("quickstart_userdefaults_desc"),
      onClick: openUserDefaultsTab,
    },
    {
      icon: <Layout className="w-5 h-5" />,
      title: t("inspect_ui"),
      description: t("quickstart_ui_desc"),
      onClick: openUIDumpTab,
    },
    {
      icon: <Globe className="w-5 h-5" />,
      title: "WebViews",
      description: t("quickstart_webview_desc"),
      onClick: openWebViewTab,
    },
    {
      icon: <Code className="w-5 h-5" />,
      title: "JSContext",
      description: t("quickstart_jsc_desc"),
      onClick: openJSCTab,
    },
    ...(platform === Platform.Fruity
      ? [
          {
            icon: <Network className="w-5 h-5" />,
            title: "HTTP Log",
            description: "Capture NSURLSession network traffic",
            onClick: openHttpLogTab,
          },
        ]
      : []),
  ];

  return (
    <div className="h-full flex flex-col items-center justify-center p-8 overflow-auto">
      <div className="max-w-3xl w-full space-y-8">
        <div className="text-center space-y-3">
          <h1 className="text-3xl font-bold">Grapefruit</h1>
          <p className="text-muted-foreground">{t("quickstart_description")}</p>
          <a
            href="https://github.com/chichou/grapefruit"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            GitHub
          </a>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {features.map((feature) => (
            <FeatureCard
              key={feature.title}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
              onClick={feature.onClick}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
