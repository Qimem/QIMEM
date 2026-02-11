import { ApiResponseViewer, Button, FormField, Panel } from "./ui";
import { ApiError, EncryptResponse } from "../lib/qimemClient";

export function EncryptionLab({ plaintext, setPlaintext, encrypted, decrypted, onEncrypt, onDecrypt, error }: {
  plaintext: string; setPlaintext: (value: string) => void; encrypted: EncryptResponse | null; decrypted: string; onEncrypt: () => void; onDecrypt: () => void; error: ApiError | null;
}) {
  return <Panel title="Encryption Lab"><div className="space-y-3"><FormField label="Plaintext"><textarea className="w-full rounded-md border border-base-border bg-base-bg p-2" rows={4} value={plaintext} onChange={(e)=>setPlaintext(e.target.value)} /></FormField><div className="flex gap-2"><Button onClick={onEncrypt}>Encrypt</Button><Button onClick={onDecrypt} disabled={!encrypted}>Decrypt</Button></div>{encrypted && <ApiResponseViewer data={encrypted} />}{decrypted && <p className="text-sm text-accent">Decrypted: {decrypted}</p>}{error && <ApiResponseViewer data={error} />}</div></Panel>;
}
