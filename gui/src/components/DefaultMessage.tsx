import { useTranslation } from "react-i18next";

export function DefaultMessage() {
  const { t } = useTranslation();

  return (
    <div className="flex h-full items-center justify-center">
      <div className="text-center">
        <p className="text-lg text-muted-foreground">{t("please_select_device")}</p>
        <p className="text-muted-foreground mt-4">{t("new_to_grapefruit")}</p>
        <p>
          <a
            href="http://github.com/chichou/grapefruit"
            target="_blank"
            className="hover:text-amber-500 transition-colors duration-200"
          >
            GitHub
          </a>
          <a
            href="https://discord.gg/pwutZNx"
            target="_blank"
            className="ml-2 hover:text-amber-500 transition-colors duration-200"
          >
            Discord
          </a>
        </p>
      </div>
    </div>
  );
}
