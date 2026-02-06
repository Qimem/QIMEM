type JsonViewerProps = {
  data: unknown;
  placeholder?: string;
};

export function JsonViewer({ data, placeholder = "No data yet." }: JsonViewerProps) {
  if (!data) {
    return (
      <div className="rounded-md border border-dashed border-base-600 bg-base-700/50 p-3 text-xs text-slate-400">
        {placeholder}
      </div>
    );
  }

  return (
    <pre className="max-h-64 overflow-auto rounded-md border border-base-600 bg-base-900/70 p-3 text-xs text-slate-100">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}
