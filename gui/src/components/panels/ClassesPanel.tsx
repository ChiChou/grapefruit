import { useTranslation } from "react-i18next";

export function ClassesPanel() {
  const { t } = useTranslation();

  return (
    <div className="h-full p-4">
      <h2 className="text-xl font-semibold mb-4">{t("classes")}</h2>
      <div className="space-y-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Application classes and methods
        </p>
      </div>
    </div>
  );
}
