export function Header() {
  return (
    <header className="mb-4 flex items-center justify-between border-b border-base-border pb-3">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">QIMEM Playground</h1>
        <p className="text-xs text-slate-400">Interactive console for QIMEM cryptography APIs.</p>
      </div>
    </header>
  );
}
