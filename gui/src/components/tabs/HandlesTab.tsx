import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

export function HandlesTab() {
  const { t } = useTranslation();
  const { api, status } = useSession();
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    setLoading(true);
    api.lsof.fds().then((fds) => {
      console.log(fds);
    });
  }, [status, api]);

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">{t("active_file_handles")}</h2>
      {loading ? (
        <p>{t("loading")}...</p>
      ) : (
        <p>{t("file_handles_loaded_check_console")}</p>
      )}
    </div>
  );
}
