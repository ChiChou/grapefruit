import { useTranslation } from "react-i18next";

export function DefaultMessage() {
  const { t } = useTranslation();

  return (
    <div className="flex h-full items-center justify-center">
      <p className="text-lg text-gray-500">{t("please_select_device")}</p>
    </div>
  );
}
