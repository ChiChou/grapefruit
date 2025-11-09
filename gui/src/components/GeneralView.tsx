import { useTranslation } from "react-i18next";

export function GeneralView() {
  const { t } = useTranslation();

  return (
    <div className="h-full p-4">
      <h2 className="text-xl font-semibold mb-4">{t("general")}</h2>
      <div className="space-y-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          General information about the application
        </p>
      </div>
    </div>
  );
}
