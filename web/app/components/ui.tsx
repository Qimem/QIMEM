import { ReactNode } from "react";

export function Panel({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section className={`glow-box rounded-md bg-base-surface p-4 ${className}`}>
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-widest text-accent-strong">{title}</h2>
      {children}
    </section>
  );
}

export function Button({ children, onClick, disabled = false, type = "button" }: { children: ReactNode; onClick?: () => void; disabled?: boolean; type?: "button" | "submit" | "reset" }) {
  return (
    <button
      type={type}
      disabled={disabled}
      onClick={onClick}
      className="glow-box-soft rounded-md bg-base-bg px-3 py-2 text-xs font-semibold uppercase tracking-wider text-accent transition hover:bg-[#171b20] disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}

export function FormField({ label, children, error }: { label: string; children: ReactNode; error?: string }) {
  return (
    <label className="block text-xs uppercase tracking-widest text-slate-400">
      {label}
      <div className="mt-2">{children}</div>
      {error && <p className="mt-1 text-[11px] text-red-300">{error}</p>}
    </label>
  );
}

export function ApiResponseViewer({ data }: { data: unknown }) {
  return (
    <pre className="glow-box-soft max-h-72 overflow-auto rounded-md bg-base-bg/80 p-3 font-mono text-xs text-slate-200">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export const inputClassName =
  "glow-box-soft w-full rounded-md bg-base-bg p-2 text-sm text-base-text outline-none placeholder:text-slate-500 focus:ring-1 focus:ring-accent";
