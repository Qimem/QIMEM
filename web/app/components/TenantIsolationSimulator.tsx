import { ApiError } from "../lib/qimemClient";
import { ApiResponseViewer, Button, FormField, Panel, inputClassName } from "./ui";

export function TenantIsolationSimulator({ activeTenant, setActiveTenant, status, onRun, error }: { activeTenant: string; setActiveTenant: (v: string) => void; status: string; onRun: () => void; error: ApiError | null; }) {
  return (
    <Panel title="Tenant Isolation Simulator">
      <div className="space-y-3">
        <FormField label="Tenant">
          <select className={inputClassName} value={activeTenant} onChange={(e) => setActiveTenant(e.target.value)}>
            <option>Tenant A</option>
            <option>Tenant B</option>
          </select>
        </FormField>
        <Button onClick={onRun}>Encrypt A then Decrypt B</Button>
        {status && <p className="text-sm">{status}</p>}
        <p className="text-xs text-slate-400">JWT remains unchanged. Isolation is demonstrated by switching only the tenant header.</p>
        {error && <ApiResponseViewer data={error} />}
      </div>
    </Panel>
  );
}
