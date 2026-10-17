import type { ComponentChildren } from 'preact';
import { useEffect } from 'preact/hooks';
import { ApiError, get } from './api.js';
import { Link, Loading, OfflineBanner, Toasts } from './components.js';
import { applyLang, t, useLang } from './i18n/index.js';
import { IconCircles, IconMonitor, IconMoon, IconPlus, IconSun, IconUser, LogoMark } from './icons.js';
import { matchRoute, navigate, useLocation } from './router.js';
import { Account } from './screens/account.js';
import { Recovery, SignIn, SignUp } from './screens/auth.js';
import { CircleHome } from './screens/circle.js';
import { CreateCircle, MyCircles } from './screens/circles.js';
import { Join } from './screens/join.js';
import { session, useStore, type User } from './store.js';
import { applyTheme, nextTheme, theme, type Theme } from './theme.js';

const THEME_ICON: Record<Theme, () => preact.JSX.Element> = {
  system: () => <IconMonitor />,
  light: () => <IconSun />,
  dark: () => <IconMoon />,
};

function Redirect({ to }: { to: string }) {
  useEffect(() => navigate(to, { replace: true }), [to]);
  return null;
}

function TopBar({ user, path }: { user: User | null; path: string }) {
  const lang = useLang();
  const th = useStore(theme);
  const Icon = THEME_ICON[th];
  return (
    <header class="topbar">
      <div class="topbar-inner">
        <Link href={user ? '/circles' : '/signin'} class="brand" aria-label={t('app.name')}>
          <LogoMark class="brand-mark" />
          <span data-testid="brand">{t('app.name')}</span>
        </Link>
        {user ? (
          <nav class="topnav" aria-label={t('nav.main')}>
            <Link href="/circles" current={path === '/circles'}>
              {t('nav.circles')}
            </Link>
            <Link href="/circles/new" current={path === '/circles/new'}>
              {t('nav.new')}
            </Link>
            <Link href="/account" current={path === '/account'}>
              {t('nav.account')}
            </Link>
          </nav>
        ) : null}
        <div class="topbar-tools">
          <button
            type="button"
            class="btn btn-ghost btn-small"
            lang={lang === 'ar' ? 'en' : 'ar'}
            aria-label={t('lang.switch.label')}
            data-testid="lang-switch"
            onClick={() => applyLang(lang === 'ar' ? 'en' : 'ar')}
          >
            {t('lang.switch')}
          </button>
          <button
            type="button"
            class="btn btn-ghost btn-icon"
            aria-label={t('theme.label', { theme: t(`theme.${th}`) })}
            title={t('theme.label', { theme: t(`theme.${th}`) })}
            data-testid="theme-switch"
            onClick={() => applyTheme(nextTheme(th))}
          >
            <Icon />
          </button>
        </div>
      </div>
    </header>
  );
}

function BottomNav({ path }: { path: string }) {
  return (
    <nav class="bottomnav" aria-label={t('nav.main')}>
      <Link href="/circles" current={path === '/circles' || path.startsWith('/circles/') && path !== '/circles/new'}>
        <IconCircles />
        {t('nav.circles')}
      </Link>
      <Link href="/circles/new" current={path === '/circles/new'}>
        <IconPlus />
        {t('nav.new')}
      </Link>
      <Link href="/account" current={path === '/account'}>
        <IconUser />
        {t('nav.account')}
      </Link>
    </nav>
  );
}

function Shell({ user, path, wide, children }: { user: User | null; path: string; wide?: boolean; children: ComponentChildren }) {
  return (
    <div class="app">
      <TopBar user={user} path={path} />
      <OfflineBanner />
      <main class={`main ${wide ? 'wide' : ''}`} id="main">
        {children}
      </main>
      <footer class="footer">
        <span>{t('app.footer')}</span> · <span class="ltr" data-testid="version">{t('app.version', { version: __DAWR_VERSION__ })}</span>
      </footer>
      {user ? <BottomNav path={path} /> : null}
      <Toasts />
    </div>
  );
}

const PUBLIC_ONLY = ['/signin', '/signup', '/recovery'];

function Routes({ path, user }: { path: string; user: User | null }) {
  if (PUBLIC_ONLY.includes(path)) {
    if (user) return <Redirect to="/circles" />;
    if (path === '/signin') return <SignIn />;
    if (path === '/signup') return <SignUp />;
    return <Recovery />;
  }
  const join = matchRoute('/join/:token', path);
  if (join) return <Join token={join.token as string} />;
  if (!user) return <Redirect to={`/signin?next=${encodeURIComponent(path + window.location.search)}`} />;
  if (path === '/' || path === '/circles') return <MyCircles />;
  if (path === '/circles/new') return <CreateCircle />;
  if (path === '/account') return <Account />;
  const circle = matchRoute('/circles/:id', path);
  if (circle) return <CircleHome id={circle.id as string} />;
  return <Redirect to="/circles" />;
}

export function App() {
  const path = useLocation();
  useLang();
  const user = useStore(session);

  useEffect(() => {
    get<{ user: User }>('/api/auth/me')
      .then((r) => session.set(r.user))
      .catch((e: unknown) => {
        // Signed out is an answer; an unreachable server is not, but there is nothing to show without one.
        session.set(e instanceof ApiError && e.offline ? null : null);
      });
  }, []);

  if (user === undefined) {
    return (
      <Shell user={null} path={path}>
        <Loading />
      </Shell>
    );
  }
  return (
    <Shell user={user} path={path} wide={path.startsWith('/circles/') && path !== '/circles/new'}>
      <Routes path={path} user={user} />
    </Shell>
  );
}
