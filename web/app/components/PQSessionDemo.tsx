import { ApiResponseViewer, Button, Panel } from "./ui";
import { ApiError, PQKeypair, PQSessionResponse } from "../lib/qimemClient";

const mask = (v?: string) => (v ? `${v.slice(0, 6)}…${v.slice(-6)}` : "—");

export function PQSessionDemo({ keypair, session, onKeypair, onSession, error }: { keypair: PQKeypair | null; session: PQSessionResponse | null; onKeypair: () => void; onSession: () => void; error: ApiError | null; }) {
  return <Panel title="Post-Quantum Session Demo"><div className="space-y-3"><div className="flex gap-2"><Button onClick={onKeypair}>Generate PQ Keypair</Button><Button onClick={onSession} disabled={!keypair}>Create Session</Button></div><p className="text-xs text-slate-400">Hybrid session = X25519 + Kyber combined with HKDF for resilient forward security.</p>{keypair && <p className="font-mono text-xs">PQ Public Key: {mask(keypair.public_key_b64)}</p>}{session && <ApiResponseViewer data={{...session, session_key_b64: mask(session.session_key_b64), kyber_ciphertext_b64: mask(session.kyber_ciphertext_b64)}} />}{error && <ApiResponseViewer data={error} />}</div></Panel>;
}
