import { useEffect, useRef, useState, type ReactNode } from "react";
import { STATE_LABEL, STATE_TONE, formatCountdown, type RequestState } from "@sbc/client";
import { Icon } from "./Icon.tsx";
import { useNow } from "../lib/data/context.tsx";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

export function Badge({ tone = "neutral", children, dot = true }: { tone?: string; children: ReactNode; dot?: boolean }) {
  return (
    <span className={cx("badge", `tone-${tone}`)}>
      {dot ? <span className="badge-dot" /> : null}
      {children}
    </span>
  );
}

/** Marks hosts, identities and requests created by the live end-to-end test run. */
export function FixtureTag({ id }: { id: string | null | undefined }) {
  if (!id || !id.startsWith("e2e-")) return null;
  return (
    <span className="fixture-tag mono" title="Created by the live end-to-end test run (scripts/e2e-testnet.ts)">
      e2e test
    </span>
  );
}

export function StateBadge({ state }: { state: RequestState }) {
  return <Badge tone={STATE_TONE[state]}>{STATE_LABEL[state]}</Badge>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx("mono", className)}>{children}</code>;
}

export function CopyButton({ text, label = "Copy", compact = false }: { text: string; label?: string; compact?: boolean }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={cx("btn btn-ghost btn-xs", compact && "btn-icon")}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1400);
        } catch {
          /* clipboard blocked */
        }
      }}
      aria-label={label}
      title={label}
    >
      <Icon name={done ? "check" : "copy"} size={14} />
      {compact ? null : <span>{done ? "Copied" : label}</span>}
    </button>
  );
}

export function Command({ children, prompt = "$", copy = true, tone }: { children: string; prompt?: string; copy?: boolean; tone?: "allowed" | "denied" }) {
  return (
    <div className={cx("cmd", tone && `cmd-${tone}`)}>
      <pre>
        {prompt ? <span className="cmd-prompt">{prompt} </span> : null}
        {children}
      </pre>
      {copy ? <CopyButton text={children} compact label="Copy command" /> : null}
    </div>
  );
}

export function KV({ items, cols = 2 }: { items: [ReactNode, ReactNode][]; cols?: number }) {
  return (
    <dl className="kv" style={{ ["--kv-cols" as string]: cols }}>
      {items.map(([k, v], i) => (
        <div key={i} className="kv-item">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Panel({ title, actions, children, className, flush }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={cx("panel", flush && "panel-flush", className)}>
      {title || actions ? (
        <header className="panel-head">
          <h3>{title}</h3>
          {actions ? <div className="panel-actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions, back }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; back?: { to: string; label: string } }) {
  return (
    <header className="page-head">
      <div>
        {back ? (
          <a className="back" href={"#" + back.to}>
            <Icon name="back" size={14} /> {back.label}
          </a>
        ) : null}
        <h1>{title}</h1>
        {subtitle ? <p className="page-sub">{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function Empty({ title, children, icon = "circle" }: { title: string; children?: ReactNode; icon?: string }) {
  return (
    <div className="empty">
      <Icon name={icon} size={18} />
      <div>
        <strong>{title}</strong>
        {children ? <p>{children}</p> : null}
      </div>
    </div>
  );
}

export function Skeleton({ lines = 3, height }: { lines?: number; height?: number }) {
  return (
    <div className="skeleton" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }).map((_, i) => (
        <span key={i} style={{ width: `${92 - i * 17}%`, height }} />
      ))}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="note note-danger" role="alert">
      <Icon name="alert" size={14} />
      <span>{error instanceof Error ? error.message : String(error)}</span>
    </div>
  );
}

/** Calm countdown to `untilMs` (chain-adjusted). */
export function Countdown({ untilMs, className }: { untilMs: number; className?: string }) {
  const now = useNow(1000);
  return <span className={cx("countdown mono", className)}>{formatCountdown(untilMs - now)}</span>;
}

export function Segmented<T extends string>({ value, onChange, options, size }: { value: T; onChange: (v: T) => void; options: { value: T; label: ReactNode }[]; size?: "sm" }) {
  return (
    <div className={cx("segmented", size === "sm" && "segmented-sm")} role="tablist">
      {options.map((o) => (
        <button key={o.value} type="button" role="tab" aria-selected={o.value === value} className={cx(o.value === value && "on")} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Dialog({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} className={cx("dialog", wide && "dialog-wide")} onClose={onClose} onCancel={onClose}>
      <header className="dialog-head">
        <h2>{title}</h2>
        <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close">
          <Icon name="x" />
        </button>
      </header>
      <div className="dialog-body">{children}</div>
      {footer ? <footer className="dialog-foot">{footer}</footer> : null}
    </dialog>
  );
}

export function Field({ label, hint, children, error }: { label: ReactNode; hint?: ReactNode; children: ReactNode; error?: string | null }) {
  return (
    <label className={cx("field", error && "field-error")}>
      <span className="field-label">{label}</span>
      {children}
      {error ? <span className="field-hint err">{error}</span> : hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

export function Chips({ options, value, onChange, mono }: { options: { value: string; label?: ReactNode }[]; value: string[]; onChange: (v: string[]) => void; mono?: boolean }) {
  return (
    <div className="chips">
      {options.map((o) => {
        const on = value.includes(o.value);
        return (
          <button
            key={o.value}
            type="button"
            className={cx("chip", on && "on", mono && "mono")}
            aria-pressed={on}
            onClick={() => onChange(on ? value.filter((x) => x !== o.value) : [...value, o.value])}
          >
            {on ? <Icon name="check" size={12} /> : null}
            {o.label ?? o.value}
          </button>
        );
      })}
    </div>
  );
}

export function Truncate({ text, head = 10, tail = 6 }: { text: string; head?: number; tail?: number }) {
  if (text.length <= head + tail + 1) return <span className="mono">{text}</span>;
  return (
    <span className="mono" title={text}>
      {text.slice(0, head)}…{text.slice(-tail)}
    </span>
  );
}
