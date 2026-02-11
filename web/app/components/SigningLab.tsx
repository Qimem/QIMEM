import { ApiResponseViewer, Button, FormField, Panel } from "./ui";
import { ApiError, SignResponse } from "../lib/qimemClient";

export function SigningLab({ message, setMessage, signResult, verifyResult, onSign, onVerify, error }: {
  message: string; setMessage: (value: string) => void; signResult: SignResponse | null; verifyResult: boolean | null; onSign: () => void; onVerify: () => void; error: ApiError | null;
}) {
  return <Panel title="Signing Lab"><div className="space-y-3"><FormField label="Message"><input className="w-full rounded-md border border-base-border bg-base-bg p-2" value={message} onChange={(e)=>setMessage(e.target.value)} /></FormField><div className="flex gap-2"><Button onClick={onSign}>Sign</Button><Button onClick={onVerify} disabled={!signResult}>Verify</Button></div>{signResult && <ApiResponseViewer data={signResult} />}{verifyResult !== null && <p className="text-sm">Verify: {String(verifyResult)}</p>}{error && <ApiResponseViewer data={error} />}</div></Panel>;
}
