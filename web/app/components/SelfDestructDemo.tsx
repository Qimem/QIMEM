import { ApiResponseViewer, Button, FormField, Panel } from "./ui";
import { ApiError, SelfDestructResponse } from "../lib/qimemClient";

export function SelfDestructDemo({ payload, setPayload, ttl, setTtl, encrypted, decryptResult, countdown, onEncrypt, onDecrypt, error }: {
  payload: string; setPayload: (v: string)=>void; ttl: number; setTtl: (v:number)=>void; encrypted: SelfDestructResponse | null; decryptResult: string; countdown: number | null; onEncrypt: ()=>void; onDecrypt: ()=>void; error: ApiError | null;
}) {
  return <Panel title="Self-Destruct Encryption Demo"><div className="space-y-3"><FormField label="Text"><input className="w-full rounded-md border border-base-border bg-base-bg p-2" value={payload} onChange={(e)=>setPayload(e.target.value)} /></FormField><FormField label="TTL (seconds)"><input type="number" className="w-full rounded-md border border-base-border bg-base-bg p-2" value={ttl} onChange={(e)=>setTtl(Number(e.target.value))} /></FormField><div className="flex gap-2"><Button onClick={onEncrypt}>Encrypt with TTL</Button><Button onClick={onDecrypt} disabled={!encrypted}>Attempt Decrypt</Button></div>{countdown !== null && <p className="text-xs text-slate-300">Countdown: {countdown}s</p>}{encrypted && <ApiResponseViewer data={encrypted} />}{decryptResult && <p className="text-sm">Decrypt result: {decryptResult}</p>}{error && <ApiResponseViewer data={error} />}</div></Panel>;
}
