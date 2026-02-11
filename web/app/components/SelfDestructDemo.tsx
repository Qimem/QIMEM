import { ApiError, SelfDestructResponse } from "../lib/qimemClient";
import { ApiResponseViewer, Button, FormField, Panel, inputClassName } from "./ui";

export function SelfDestructDemo({ payload, setPayload, ttl, setTtl, encrypted, decryptResult, countdown, onEncrypt, onDecrypt, error }: {
  payload: string;
  setPayload: (v: string) => void;
  ttl: number;
  setTtl: (v: number) => void;
  encrypted: SelfDestructResponse | null;
  decryptResult: string;
  countdown: number | null;
  onEncrypt: () => void;
  onDecrypt: () => void;
  error: ApiError | null;
}) {
  return (
    <Panel title="Self-Destruct Encryption Demo">
      <div className="space-y-3">
        <FormField label="Text">
          <input className={inputClassName} value={payload} onChange={(e) => setPayload(e.target.value)} />
        </FormField>
        <FormField label="TTL (seconds)">
          <input type="number" min={1} className={inputClassName} value={ttl} onChange={(e) => setTtl(Number(e.target.value) || 0)} />
        </FormField>
        <div className="flex gap-2">
          <Button onClick={onEncrypt}>Encrypt with TTL</Button>
          <Button onClick={onDecrypt} disabled={!encrypted}>Attempt Decrypt</Button>
        </div>
        {countdown !== null && <p className="text-xs text-slate-300">Countdown: {countdown}s</p>}
        {encrypted && <ApiResponseViewer data={encrypted} />}
        {decryptResult && <p className="text-sm">{decryptResult}</p>}
        {error && <ApiResponseViewer data={error} />}
      </div>
    </Panel>
  );
}
