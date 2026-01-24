import { useSession } from "@/context/SessionContext";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PlistView, type PlistValue } from "@/components/UnifiedPlistViewer";

export function InfoPlistTab() {
  const { t } = useTranslation();
  const { api } = useSession();
  const [loading, setLoading] = useState<boolean>(false);
  const [xml, setXml] = useState<string>("");
  const [plistData, setPlistData] = useState<PlistValue | null>(null);

  useEffect(() => {
    if (!api) return;

    setLoading(true);
    api.info
      .plist()
      .then(({ xml, value }) => {
        setXml(xml);
        setPlistData(value);
      })
      .finally(() => setLoading(false));
  }, [api]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("loading")}
      </div>
    );
  }

  return <PlistView xml={xml} value={plistData} filename="Info.plist" />;
}
