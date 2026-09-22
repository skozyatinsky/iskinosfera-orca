import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import * as ExpoLocalization from 'expo-localization'

import en from './locales/en.json'
import ru from './locales/ru.json'
import tr from './locales/tr.json'

const LOCALES: Record<string, { translation: Record<string, unknown> }> = {
  en: { translation: en },
  ru: { translation: ru },
  tr: { translation: tr }
}

const detectLanguage = (): string => {
  try {
    const locales = ExpoLocalization.getLocales()
    if (locales.length > 0) {
      const primary = locales[0].languageCode
      if (primary === 'ru' || primary === 'tr') { return primary }
    }
  } catch {}
  return 'en'
}

i18n.use(initReactI18next).init({
  resources: LOCALES,
  lng: detectLanguage(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
  react: { useSuspense: false }
})

export default i18n