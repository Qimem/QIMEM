import { ApiError, EncryptResponse } from "../lib/qimemClient";
import { ApiResponseViewer, Button, FormField, Panel, inputClassName } from "./ui";

export function EncryptionLab({ plaintext, setPlaintext, encrypted, decrypted, onEncrypt, onDecrypt, error }: {
  plaintext: string;
  setPlaintext: (value: string) => void;
  encrypted: EncryptResponse | null;
  decrypted: string;
  onEncrypt: () => void;
  onDecrypt: () => void;
  error: ApiError | null;
}) {
  return (
    <Panel title="Encryption Lab">
      <div className="space-y-3">
        <FormField label="Plaintext">
          <textarea className={`${inputClassName} min-h-24`} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
        </FormField>
        <div className="flex gap-2">
          <Button onClick={onEncrypt}>Encrypt</Button>
          <Button onClick={onDecrypt} disabled={!encrypted}>Decrypt</Button>
        </div>
        {encrypted && <ApiResponseViewer data={encrypted} />}
        {decrypted && <p className="rounded-md bg-base-bg/70 p-2 font-mono text-sm text-accent">{decrypted}</p>}
        {error && <ApiResponseViewer data={error} />}
      </div>
    </Panel>
  );
}
