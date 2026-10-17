import { applyLang, t, useLang } from './i18n/index.js';
import { useLocation } from './router.js';

function Home() {
  const lang = useLang();
  return (
    <main class="page">
      <h1>{t('app.name')}</h1>
      <p>{t('app.tagline')}</p>
      <p class="muted" data-testid="version">
        {t('app.version', { version: __DAWR_VERSION__ })}
      </p>
      <button
        type="button"
        class="btn"
        aria-label={t('lang.switch.label')}
        onClick={() => applyLang(lang === 'ar' ? 'en' : 'ar')}
      >
        {t('lang.switch')}
      </button>
    </main>
  );
}

export function App() {
  useLocation();
  useLang();
  return <Home />;
}
