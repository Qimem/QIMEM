const sections = ["Encryption Lab", "Signing Lab", "Post-Quantum Session", "Self-Destruct Demo", "Tenant Isolation", "Audit Chain", "Help & Info"];

export function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-64 border-r border-base-border bg-base-surface p-5">
      <p className="text-xs uppercase tracking-[0.3em] text-accent">QIMEM</p>
      <ul className="mt-6 space-y-2 text-sm text-slate-300">
        {sections.map((section) => (
          <li key={section} className="rounded px-2 py-1 hover:bg-base-bg">{section}</li>
        ))}
      </ul>
    </aside>
  );
}
