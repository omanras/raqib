import type { ComponentChildren, JSX } from 'preact';
import { useId, useState } from 'preact/hooks';
import { t, tx, type MessageKeyOf } from './i18n/index.js';
import { IconAlert, IconCheck, IconCopy, IconInfo, IconOffline } from './icons.js';
import { onLinkClick } from './router.js';
import { connection, dismissToast, toast, toasts, useStore } from './store.js';
import { localTime, money } from './format.js';

// ---------------------------------------------------------------- links and buttons

export function Link(props: { href: string; class?: string; children: ComponentChildren; current?: boolean; 'aria-label'?: string }) {
  return (
    <a
      href={props.href}
      class={props.class}
      aria-current={props.current ? 'page' : undefined}
      aria-label={props['aria-label']}
      onClick={(e) => onLinkClick(e as unknown as MouseEvent, props.href)}
    >
      {props.children}
    </a>
  );
}

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-solid';

export function Button(
  props: {
    variant?: ButtonVariant;
    small?: boolean;
    block?: boolean;
    busy?: boolean;
    children: ComponentChildren;
  } & Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'class'>,
) {
  const { variant = 'secondary', small, block, busy, children, disabled, type, ...rest } = props;
  const cls = ['btn', variant !== 'secondary' ? `btn-${variant}` : '', small ? 'btn-small' : '', block ? 'btn-block' : '']
    .filter(Boolean)
    .join(' ');
  return (
    <button {...rest} type={(type as 'button' | 'submit' | undefined) ?? 'button'} class={cls} disabled={Boolean(disabled) || busy} aria-busy={busy ? 'true' : undefined}>
      {busy ? <span class="spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

export function LinkButton(props: { href: string; variant?: ButtonVariant; small?: boolean; children: ComponentChildren }) {
  const cls = ['btn', props.variant && props.variant !== 'secondary' ? `btn-${props.variant}` : '', props.small ? 'btn-small' : '']
    .filter(Boolean)
    .join(' ');
  return (
    <Link href={props.href} class={cls}>
      {props.children}
    </Link>
  );
}

// ---------------------------------------------------------------- form fields

export function Field(props: { label: string; hint?: ComponentChildren; error?: string | null; children: (id: string, describedBy: string | undefined) => ComponentChildren; optional?: boolean }) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = [props.hint ? hintId : '', props.error ? errId : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div class="field">
      <label for={id}>
        {props.label}
        {props.optional ? <span class="muted small"> ({t('common.optional')})</span> : null}
      </label>
      {props.children(id, describedBy)}
      {props.hint ? (
        <span class="hint" id={hintId}>
          {props.hint}
        </span>
      ) : null}
      {props.error ? (
        <span class="error" id={errId} role="alert">
          {props.error}
        </span>
      ) : null}
    </div>
  );
}

export function TextField(props: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  hint?: ComponentChildren;
  error?: string | null;
  type?: string;
  autocomplete?: string;
  required?: boolean;
  optional?: boolean;
  maxLength?: number;
  inputMode?: 'text' | 'decimal' | 'numeric';
  dir?: 'ltr' | 'rtl' | 'auto';
  name?: string;
  class?: string;
  placeholder?: string;
}) {
  return (
    <Field label={props.label} hint={props.hint} error={props.error} optional={props.optional}>
      {(id, describedBy) => (
        <input
          id={id}
          name={props.name}
          class={`input ${props.class ?? ''}`}
          type={props.type ?? 'text'}
          value={props.value}
          autocomplete={props.autocomplete}
          required={props.required}
          maxLength={props.maxLength}
          inputMode={props.inputMode}
          dir={props.dir}
          placeholder={props.placeholder}
          aria-invalid={props.error ? 'true' : undefined}
          aria-describedby={describedBy}
          onInput={(e) => props.onInput((e.currentTarget as HTMLInputElement).value)}
        />
      )}
    </Field>
  );
}

export function PasswordField(props: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  autocomplete: 'current-password' | 'new-password';
  hint?: string | null;
  error?: string | null;
  showStrength?: boolean;
  name?: string;
}) {
  const [show, setShow] = useState(false);
  const length = [...props.value].length;
  const strength = props.showStrength && props.value ? (length >= 10 ? t('auth.passwordStrength.ok') : t('auth.passwordStrength.short', { n: 10 - length })) : null;
  return (
    <Field label={props.label} hint={strength ?? props.hint} error={props.error}>
      {(id, describedBy) => (
        <div class="stack-s">
          <input
            id={id}
            name={props.name}
            class="input"
            type={show ? 'text' : 'password'}
            value={props.value}
            autocomplete={props.autocomplete}
            required
            maxLength={1024}
            dir="ltr"
            aria-invalid={props.error ? 'true' : undefined}
            aria-describedby={describedBy}
            onInput={(e) => props.onInput((e.currentTarget as HTMLInputElement).value)}
          />
          <label class="check small">
            <input type="checkbox" checked={show} onChange={(e) => setShow((e.currentTarget as HTMLInputElement).checked)} />
            <span>{t('auth.showPassword')}</span>
          </label>
        </div>
      )}
    </Field>
  );
}

export function TextArea(props: { label: string; value: string; onInput: (v: string) => void; hint?: string | null; error?: string | null; optional?: boolean; maxLength?: number; name?: string }) {
  return (
    <Field label={props.label} hint={props.hint} error={props.error} optional={props.optional}>
      {(id, describedBy) => (
        <textarea
          id={id}
          name={props.name}
          class="textarea"
          value={props.value}
          maxLength={props.maxLength}
          dir="auto"
          aria-invalid={props.error ? 'true' : undefined}
          aria-describedby={describedBy}
          onInput={(e) => props.onInput((e.currentTarget as HTMLTextAreaElement).value)}
        />
      )}
    </Field>
  );
}

export function Select<V extends string>(props: {
  label: string;
  value: V;
  options: { value: V; label: string }[];
  onChange: (v: V) => void;
  hint?: string | null;
  name?: string;
}) {
  return (
    <Field label={props.label} hint={props.hint}>
      {(id, describedBy) => (
        <select
          id={id}
          name={props.name}
          class="select"
          value={props.value}
          aria-describedby={describedBy}
          onChange={(e) => props.onChange((e.currentTarget as HTMLSelectElement).value as V)}
        >
          {props.options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      )}
    </Field>
  );
}

export function Segmented<V extends string>(props: { label: string; value: V; options: { value: V; label: string }[]; onChange: (v: V) => void }) {
  return (
    <div class="field">
      <span class="label" id={`seg-${props.label}`}>
        {props.label}
      </span>
      <div class="segmented" role="group" aria-label={props.label}>
        {props.options.map((o) => (
          <button key={o.value} type="button" aria-pressed={o.value === props.value ? 'true' : 'false'} onClick={() => props.onChange(o.value)}>
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export function Checkbox(props: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void; name?: string }) {
  return (
    <label class="check">
      <input type="checkbox" name={props.name} checked={props.checked} onChange={(e) => props.onChange((e.currentTarget as HTMLInputElement).checked)} />
      <span>
        <span>{props.label}</span>
        {props.hint ? <span class="hint muted xsmall block">{props.hint}</span> : null}
      </span>
    </label>
  );
}

// ---------------------------------------------------------------- display

export type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'danger' | 'info';

export function Chip(props: { tone?: Tone; children: ComponentChildren; plain?: boolean; testId?: string }) {
  const tone = props.tone && props.tone !== 'neutral' ? `chip-${props.tone}` : '';
  return (
    <span class={`chip ${tone} ${props.plain ? 'chip-plain' : ''}`} data-testid={props.testId}>
      {props.children}
    </span>
  );
}

const STATUS_TONE: Record<string, Tone> = { draft: 'neutral', drawing: 'info', active: 'ok', completed: 'accent', cancelled: 'danger' };

export function StatusChip({ status }: { status: string }) {
  return (
    <Chip tone={STATUS_TONE[status] ?? 'neutral'} testId="status-chip">
      {t(`status.${status}` as MessageKeyOf<'status'>)}
    </Chip>
  );
}

export function RoleChip({ role }: { role: string }) {
  return (
    <Chip tone={role === 'organizer' ? 'accent' : 'neutral'} plain testId="role-chip">
      {t(`role.${role}` as MessageKeyOf<'role'>)}
    </Chip>
  );
}

export function Notice(props: { tone?: 'info' | 'warn' | 'danger' | 'ok'; children: ComponentChildren; class?: string; role?: 'alert' | 'status' }) {
  const tone = props.tone ?? 'info';
  const Icon = tone === 'ok' ? IconCheck : tone === 'info' ? IconInfo : IconAlert;
  return (
    <div class={`notice ${tone !== 'info' ? `notice-${tone}` : ''} ${props.class ?? ''}`} role={props.role}>
      <Icon />
      <div class="grow">{props.children}</div>
    </div>
  );
}

export function EmptyState(props: { icon?: ComponentChildren; title: string; text: string; action?: ComponentChildren }) {
  return (
    <div class="empty">
      {props.icon}
      <h2>{props.title}</h2>
      <p>{props.text}</p>
      {props.action ? <div class="row center">{props.action}</div> : null}
    </div>
  );
}

export function Loading() {
  return (
    <p class="muted row" role="status">
      <span class="spinner" aria-hidden="true" />
      {t('app.loading')}
    </p>
  );
}

export function CopyButton(props: { text: string; label?: string; small?: boolean; testId?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.text);
      setDone(true);
      toast(t('common.copied'));
      setTimeout(() => setDone(false), 2000);
    } catch {
      toast(t('common.copyFailed'), 'error');
    }
  };
  return (
    <Button small={props.small} onClick={() => void copy()} data-testid={props.testId}>
      {done ? <IconCheck /> : <IconCopy />}
      {props.label ?? t('common.copy')}
    </Button>
  );
}

/** Saves text as a file on the device (a local blob; nothing leaves the browser). */
export function downloadText(filename: string, text: string, type = 'text/plain;charset=utf-8'): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** An amount with its currency as one left-to-right unit inside any sentence. */
export function Money(props: { amount: number; currency: string; testId?: string }) {
  return (
    <bdi dir="ltr" class="amount" data-testid={props.testId}>
      {money(props.amount, props.currency)}
    </bdi>
  );
}

/** Dates, ids and other Latin tokens inside a sentence. */
export function Ltr(props: { children: ComponentChildren }) {
  return <bdi dir="ltr">{props.children}</bdi>;
}

// ---------------------------------------------------------------- app-wide

export function Toasts() {
  const list = useStore(toasts);
  return (
    <div class="toasts" aria-live="polite" aria-atomic="false">
      {list.map((x) => (
        <div key={x.id} class={`toast ${x.kind === 'error' ? 'toast-error' : ''}`} role={x.kind === 'error' ? 'alert' : 'status'} data-testid={`toast-${x.kind}`}>
          <div class="toast-body">
            {x.text}
            {x.requestId ? (
              <span class="request-id" data-testid="toast-request-id">
                {tx('common.requestId', { id: <Ltr>{x.requestId}</Ltr> })}
              </span>
            ) : null}
          </div>
          <button type="button" aria-label={t('common.dismiss')} onClick={() => dismissToast(x.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

/** A10: when the server cannot be reached, say so, and say how old what is shown is. */
export function OfflineBanner() {
  const state = useStore(connection.store);
  if (state.online) return null;
  return (
    <div class="notice notice-warn offline-banner" role="alert" data-testid="offline-banner">
      <IconOffline />
      <span>{state.lastOkAt ? t('offline.banner', { time: localTime(state.lastOkAt) }) : t('offline.bannerNever')}</span>
    </div>
  );
}
