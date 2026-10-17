import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { Link, Loading, Notice, RoleChip, StatusChip } from '../../components.js';
import { errorText } from '../../errors.js';
import { useApi, useTitle, type Loaded } from '../../hooks.js';
import { t, useLang } from '../../i18n/index.js';
import { IconBack } from '../../icons.js';
import type { CircleView } from '../../types.js';

export type CircleTab = 'overview' | 'members' | 'rounds' | 'ledger' | 'statement' | 'draw' | 'settings' | 'audit';

export interface CircleProps {
  view: CircleView;
  /** Re-fetches the circle (header, members, rounds) after a change. */
  reload: () => Promise<void>;
  /** Bumped after every change, so screens with their own data fetch again. */
  version: number;
  changed: () => void;
}

interface TabDef {
  tab: CircleTab;
  path: string;
  organizerOnly?: boolean;
}

/** Tabs in order. */
export const TABS: TabDef[] = [
  { tab: 'overview', path: '' },
  { tab: 'members', path: '/members' },
  { tab: 'rounds', path: '/rounds' },
  { tab: 'ledger', path: '/ledger' },
  { tab: 'statement', path: '/statement' },
  { tab: 'draw', path: '/draw' },
  { tab: 'settings', path: '/settings', organizerOnly: true },
  { tab: 'audit', path: '/audit', organizerOnly: true },
];

export function CircleShell(props: { id: string; tab: CircleTab; children: (p: CircleProps) => ComponentChildren }) {
  useLang();
  const view: Loaded<CircleView> = useApi<CircleView>(`/api/circles/${encodeURIComponent(props.id)}`);
  const [version, setVersion] = useState(0);
  useTitle(view.data?.circle.name ?? '');
  if (view.loading && !view.data) return <Loading />;
  if (!view.data) return <Notice tone="danger">{errorText(view.error)}</Notice>;
  const data = view.data;
  const base = `/circles/${data.circle.id}`;
  const tabs = TABS.filter((x) => !x.organizerOnly || data.me.role === 'organizer');
  const changed = () => {
    setVersion((v) => v + 1);
    void view.reload();
  };
  return (
    <div>
      <div class="circle-head">
        <Link href="/circles" class="muted small row">
          <IconBack class="small-icon" />
          {t('circle.back')}
        </Link>
        <h1 dir="auto" data-testid="circle-title">
          {data.circle.name}
        </h1>
        <div class="row">
          <StatusChip status={data.circle.status} />
          <RoleChip role={data.me.role} />
        </div>
      </div>
      <nav class="tabs" aria-label={t('tab.label')}>
        {tabs.map((x) => (
          <Link key={x.tab} href={`${base}${x.path}`} current={x.tab === props.tab}>
            {t(`tab.${x.tab}`)}
          </Link>
        ))}
      </nav>
      {props.children({ view: data, reload: view.reload, version, changed })}
    </div>
  );
}
