import type { ReactNode } from "react";

type PanelProps = {
  title: string;
  description?: string;
  children: ReactNode;
  className?: string;
};

export function Panel({ title, description, children, className }: PanelProps) {
  return (
    <section
      className={`rounded-md border border-base-600 bg-base-800/90 p-6 shadow-panel ${className ?? ""}`}
    >
      <div className="mb-4">
        <h2 className="text-sm font-semibold uppercase tracking-[0.3em] text-slate-300">
          {title}
        </h2>
        {description ? (
          <p className="mt-2 text-xs text-slate-400">{description}</p>
        ) : null}
      </div>
      <div className="space-y-4 text-sm text-slate-200">{children}</div>
    </section>
  );
}
