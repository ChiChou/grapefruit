import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en/translation.json";
import cn from "./locales/cn/translation.json";

const resources = {
  en: { translation: en },
  cn: { translation: cn },
};

i18n.use(initReactI18next).init({
  resources,
  lng: "cn",
  fallbackLng: "en",
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
