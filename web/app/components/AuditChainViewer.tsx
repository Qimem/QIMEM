import { ApiError, AuditEntry } from "../lib/qimemClient";
import { ApiResponseViewer, Button, Panel } from "./ui";

export function AuditChainViewer({ entries, verification, onRefresh, onVerify, error }: {
  entries: AuditEntry[];
  verification: Record<string, boolean>;
  onRefresh: () => void;
  onVerify: () => void;
  error: ApiError | null;
}) {
  return (
    <Panel title="Audit Chain Viewer">
      <div className="space-y-3">
        <div className="flex gap-2">
          <Button onClick={onRefresh}>Fetch Audit Chain</Button>
          <Button onClick={onVerify} disabled={!entries.length}>Verify Chain</Button>
        </div>
        {entries.map((entry) => (
          <div key={entry.id} className={`glow-box-soft rounded-md bg-base-bg/60 p-2 text-xs ${verification[entry.id] === false ? "border-red-400 text-red-200" : ""}`}>
            <p>[ {entry.event_type} ]</p>
            <p className="font-mono break-all">Hash: {entry.event_hash_b64}</p>
            <p className="font-mono break-all">Prev: {entry.prev_hash_b64 ?? "—"}</p>
            <p>Timestamp: {new Date(entry.created_at * 1000).toLocaleString()}</p>
          </div>
        ))}
        {error && <ApiResponseViewer data={error} />}
      </div>
    </Panel>
  );
}
