import { ApiResponseViewer, Button, FormField, Panel } from "./ui";
import { ApiError } from "../lib/qimemClient";

export function TenantIsolationSimulator({ activeTenant, setActiveTenant, status, onRun, error }: { activeTenant: string; setActiveTenant: (v:string)=>void; status: string; onRun: ()=>void; error: ApiError | null; }) {
  return <Panel title="Tenant Isolation Simulator"><div className="space-y-3"><FormField label="Tenant"><select className="w-full rounded-md border border-base-border bg-base-bg p-2" value={activeTenant} onChange={(e)=>setActiveTenant(e.target.value)}><option>Tenant A</option><option>Tenant B</option></select></FormField><Button onClick={onRun}>Encrypt A then decrypt B</Button>{status && <p className="text-sm">{status}</p>}<p className="text-xs text-slate-400">JWT remains unchanged. Only X-Tenant-ID changes per simulation to prove isolation.</p>{error && <ApiResponseViewer data={error} />}</div></Panel>;
}
