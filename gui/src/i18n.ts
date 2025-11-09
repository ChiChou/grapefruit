import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en/translation.json";
import cn from "./locales/cn/translation.json";

const resources = {
  en: { translation: en },
  cn: { translation: cn },
};

const lng =
  localStorage.getItem("language") ||
  (navigator.language.match(/^zh-?/i) ? "cn" : "en");

i18n.use(initReactI18next).init({
  resources,
  lng,
  fallbackLng: "en",
  interpolation: {
    escapeValue: false,
  },
});

i18n.on("languageChanged", (lng) => {
  localStorage.setItem("language", lng);
});

export default i18n;
