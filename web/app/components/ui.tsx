import { ReactNode } from "react";

export function Panel({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-md border border-base-border bg-base-surface p-4 shadow-panel ${className}`}>
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-widest text-slate-300">{title}</h2>
      {children}
    </section>
  );
}

export function Button({ children, onClick, disabled = false }: { children: ReactNode; onClick?: () => void; disabled?: boolean }) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className="rounded-md border border-accent px-3 py-2 text-xs font-semibold uppercase tracking-wider text-accent transition disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}

export function FormField({
  label,
  children,
  error,
}: {
  label: string;
  children: ReactNode;
  error?: string;
}) {
  return (
    <label className="block text-xs uppercase tracking-widest text-slate-400">
      {label}
      <div className="mt-2">{children}</div>
      {error && <p className="mt-1 text-[11px] text-red-300">{error}</p>}
    </label>
  );
}

export function ApiResponseViewer({ data }: { data: unknown }) {
  return <pre className="max-h-72 overflow-auto rounded-md border border-base-border bg-base-bg/70 p-3 font-mono text-xs text-slate-200">{JSON.stringify(data, null, 2)}</pre>;
}
