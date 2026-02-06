"use client";

import { useEffect, useMemo, useState } from "react";
import { Panel } from "./components/Panel";
import { JsonViewer } from "./components/JsonViewer";
import {
  ApiError,
  AuditLogEntry,
  KmsDecryptResponse,
  KmsEncryptResponse,
  KmsSignResponse,
  KmsVerifyResponse,
  PqKeypairResponse,
  PqSessionResponse,
  PqX25519Response,
  createQimemClient,
} from "../lib/qimem-client";

const API_BASE_URL = process.env.NEXT_PUBLIC_QIMEM_API_BASE_URL ?? "http://localhost:8080";

const navItems = [
  { id: "encryption", label: "Encryption Lab" },
  { id: "signing", label: "Signing Lab" },
  { id: "pq", label: "Post-Quantum Session" },
  { id: "self-destruct", label: "Self-Destruct Demo" },
  { id: "isolation", label: "Tenant Isolation" },
  { id: "audit", label: "Audit Chain Viewer" },
];

type UiError = ApiError;

type Countdown = {
  expiresAt?: number | null;
  remainingSeconds?: number | null;
};

function toBase64(value: string) {
  return btoa(new TextEncoder().encode(value).reduce((data, byte) => data + String.fromCharCode(byte), ""));
}

function fromBase64(value: string) {
  const decoded = atob(value);
  const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function bytesFromBase64(value: string) {
  const decoded = atob(value);
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

function base64FromBytes(bytes: Uint8Array) {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
}

function maskSecret(value?: string | null) {
  if (!value) return "—";
  if (value.length <= 12) return value;
  return `${value.slice(0, 6)}…${value.slice(-6)}`;
}

function formatTimestamp(value?: number | null) {
  if (!value) return "—";
  return new Date(value * 1000).toLocaleString();
}

function normalizeError(error: unknown): UiError {
  if (typeof error === "object" && error && "status" in error && "message" in error) {
    return error as UiError;
  }
  return { status: 500, message: "Unexpected error", details: error };
}

async function sha256Base64(payload: object) {
  if (!globalThis.crypto?.subtle) {
    return null;
  }
  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoded);
  return base64FromBytes(new Uint8Array(digest));
}

export default function Home() {
  const [jwt, setJwt] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [devPanelOpen, setDevPanelOpen] = useState(false);
  const [draftJwt, setDraftJwt] = useState("");
  const [draftTenant, setDraftTenant] = useState("");
  const [mockMode, setMockMode] = useState(false);

  const client = useMemo(() => createQimemClient({ baseUrl: API_BASE_URL, jwt, tenantId }), [jwt, tenantId]);

  const [plaintext, setPlaintext] = useState("");
  const [encryptResponse, setEncryptResponse] = useState<KmsEncryptResponse | null>(null);
  const [decryptResponse, setDecryptResponse] = useState<KmsDecryptResponse | null>(null);
  const [encryptError, setEncryptError] = useState<UiError | null>(null);
  const [decryptError, setDecryptError] = useState<UiError | null>(null);

  const [signMessage, setSignMessage] = useState("");
  const [signResponse, setSignResponse] = useState<KmsSignResponse | null>(null);
  const [verifyResponse, setVerifyResponse] = useState<KmsVerifyResponse | null>(null);
  const [signError, setSignError] = useState<UiError | null>(null);
  const [verifyError, setVerifyError] = useState<UiError | null>(null);

  const [pqKeypair, setPqKeypair] = useState<PqKeypairResponse | null>(null);
  const [pqX25519, setPqX25519] = useState<PqX25519Response | null>(null);
  const [pqSession, setPqSession] = useState<PqSessionResponse | null>(null);
  const [pqError, setPqError] = useState<UiError | null>(null);

  const [selfDestructText, setSelfDestructText] = useState("");
  const [selfDestructTtl, setSelfDestructTtl] = useState(60);
  const [selfDestructPassphrase, setSelfDestructPassphrase] = useState("");
  const [selfDestructKey, setSelfDestructKey] = useState<string | null>(null);
  const [selfDestructEncrypt, setSelfDestructEncrypt] = useState<unknown>(null);
  const [selfDestructDecrypt, setSelfDestructDecrypt] = useState<string | null>(null);
  const [selfDestructDecryptRaw, setSelfDestructDecryptRaw] = useState<unknown>(null);
  const [selfDestructError, setSelfDestructError] = useState<UiError | null>(null);
  const [countdown, setCountdown] = useState<Countdown>({});

  const [tenantA, setTenantA] = useState("");
  const [tenantB, setTenantB] = useState("");
  const [isolationCipher, setIsolationCipher] = useState<KmsEncryptResponse | null>(null);
  const [isolationStatus, setIsolationStatus] = useState("");
  const [isolationError, setIsolationError] = useState<UiError | null>(null);

  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditError, setAuditError] = useState<UiError | null>(null);
  const [auditVerification, setAuditVerification] = useState<Record<string, boolean>>({});

  const isReady = jwt.length > 0 && tenantId.length > 0;

  useEffect(() => {
    setEncryptResponse(null);
    setDecryptResponse(null);
    setEncryptError(null);
    setDecryptError(null);
    setSignResponse(null);
    setVerifyResponse(null);
    setSignError(null);
    setVerifyError(null);
    setPqKeypair(null);
    setPqX25519(null);
    setPqSession(null);
    setPqError(null);
    setSelfDestructEncrypt(null);
    setSelfDestructDecrypt(null);
    setSelfDestructDecryptRaw(null);
    setSelfDestructError(null);
    setIsolationCipher(null);
    setIsolationStatus("");
    setIsolationError(null);
    setAuditLogs([]);
    setAuditError(null);
    setAuditVerification({});
  }, [jwt, tenantId]);

  useEffect(() => {
    if (!countdown.expiresAt) {
      return;
    }
    const interval = setInterval(() => {
      const remaining = Math.max(0, countdown.expiresAt! - Math.floor(Date.now() / 1000));
      setCountdown((prev) => ({ ...prev, remainingSeconds: remaining }));
    }, 1000);
    return () => clearInterval(interval);
  }, [countdown.expiresAt]);

  const handleEncrypt = async () => {
    setEncryptError(null);
    setDecryptError(null);
    setDecryptResponse(null);
    try {
      const response = await client.kmsEncrypt(toBase64(plaintext));
      setEncryptResponse(response);
    } catch (error) {
      setEncryptError(normalizeError(error));
    }
  };

  const handleDecrypt = async () => {
    setDecryptError(null);
    setDecryptResponse(null);
    if (!encryptResponse) {
      setDecryptError({ status: 400, message: "Encrypt data first" });
      return;
    }
    try {
      const response = await client.kmsDecrypt({
        ciphertext_b64: encryptResponse.ciphertext_b64,
        wrapped_dek_b64: encryptResponse.wrapped_dek_b64,
        key_version: encryptResponse.key_version,
        nonce_b64: encryptResponse.nonce_b64,
        algorithm: encryptResponse.algorithm,
      });
      setDecryptResponse(response);
    } catch (error) {
      setDecryptError(normalizeError(error));
    }
  };

  const handleSign = async () => {
    setSignError(null);
    setVerifyError(null);
    setVerifyResponse(null);
    try {
      const response = await client.kmsSign(toBase64(signMessage));
      setSignResponse(response);
    } catch (error) {
      setSignError(normalizeError(error));
    }
  };

  const handleVerify = async () => {
    if (!signResponse) {
      setVerifyError({ status: 400, message: "Sign a message first" });
      return;
    }
    setVerifyError(null);
    try {
      const response = await client.kmsVerify({
        message_b64: toBase64(signMessage),
        public_key_b64: signResponse.public_key_b64,
        signature_b64: signResponse.signature_b64,
      });
      setVerifyResponse(response);
    } catch (error) {
      setVerifyError(normalizeError(error));
    }
  };

  const handlePqSession = async () => {
    setPqError(null);
    try {
      const [keypair, x25519] = await Promise.all([client.pqKeypair(), client.pqX25519()]);
      setPqKeypair(keypair);
      setPqX25519(x25519);
      const session = await client.pqSession({
        client_x25519_public_key_b64: x25519.public_key_b64,
        client_kyber_public_key_b64: keypair.public_key_b64,
      });
      setPqSession(session);
    } catch (error) {
      setPqError(normalizeError(error));
    }
  };

  const handleSelfDestructEncrypt = async () => {
    setSelfDestructError(null);
    setSelfDestructDecrypt(null);
    setCountdown({});
    try {
      const derived = await client.deriveKey(selfDestructPassphrase);
      setSelfDestructKey(derived.key_b64);
      const response = await client.legacyEncrypt({
        plaintext_b64: toBase64(selfDestructText),
        key_b64: derived.key_b64,
        expires_in_seconds: selfDestructTtl,
      });
      setSelfDestructEncrypt(response);
      const expiresAt = response.expires_at ?? null;
      setCountdown({
        expiresAt,
        remainingSeconds: expiresAt ? Math.max(0, expiresAt - Math.floor(Date.now() / 1000)) : null,
      });
    } catch (error) {
      setSelfDestructError(normalizeError(error));
    }
  };

  const handleSelfDestructDecrypt = async () => {
    setSelfDestructError(null);
    setSelfDestructDecryptRaw(null);
    if (!selfDestructEncrypt || !selfDestructKey) {
      setSelfDestructError({ status: 400, message: "Encrypt data first" });
      return;
    }
    try {
      const response = await client.legacyDecrypt({
        ciphertext_b64: (selfDestructEncrypt as { ciphertext_b64: string }).ciphertext_b64,
        key_b64: selfDestructKey,
      });
      setSelfDestructDecrypt(fromBase64(response.plaintext_b64));
      setSelfDestructDecryptRaw(response);
    } catch (error) {
      setSelfDestructError(normalizeError(error));
    }
  };

  const handleIsolationEncrypt = async () => {
    setIsolationError(null);
    setIsolationStatus("");
    try {
      const response = await client.rawRequest<KmsEncryptResponse>(
        "/v1/kms/encrypt",
        { method: "POST", body: JSON.stringify({ plaintext_b64: toBase64("Tenant isolation test") }) },
        { tenantId: tenantA || tenantId },
      );
      setIsolationCipher(response);
      setIsolationStatus("Encrypted under Tenant A.");
    } catch (error) {
      setIsolationError(normalizeError(error));
    }
  };

  const handleIsolationDecrypt = async () => {
    if (!isolationCipher) {
      setIsolationError({ status: 400, message: "Encrypt under Tenant A first" });
      return;
    }
    setIsolationError(null);
    try {
      await client.rawRequest<KmsDecryptResponse>(
        "/v1/kms/decrypt",
        {
          method: "POST",
          body: JSON.stringify({
            ciphertext_b64: isolationCipher.ciphertext_b64,
            wrapped_dek_b64: isolationCipher.wrapped_dek_b64,
            key_version: isolationCipher.key_version,
            nonce_b64: isolationCipher.nonce_b64,
            algorithm: isolationCipher.algorithm,
          }),
        },
        { tenantId: tenantB || tenantId },
      );
      setIsolationStatus("Unexpected success (check tenant IDs and JWT).");
    } catch (error) {
      const normalized = normalizeError(error);
      setIsolationError(normalized);
      setIsolationStatus("Cryptographic tenant isolation enforced.");
    }
  };

  const handleAuditRefresh = async () => {
    setAuditError(null);
    try {
      const logs = await client.auditLogs(25);
      setAuditLogs(logs);
      const verification: Record<string, boolean> = {};
      for (const entry of logs) {
        const prevHashBytes = entry.prev_hash_b64 ? Array.from(bytesFromBase64(entry.prev_hash_b64)) : null;
        const payload = {
          tenant_id: entry.tenant_id,
          event_type: entry.event_type,
          metadata: entry.metadata,
          prev_hash: prevHashBytes,
        };
        const digest = await sha256Base64(payload);
        if (digest) {
          verification[entry.id] = digest === entry.event_hash_b64;
        }
      }
      setAuditVerification(verification);
    } catch (error) {
      setAuditError(normalizeError(error));
    }
  };

  const clearSensitive = () => {
    setJwt("");
    setTenantId("");
    setDraftJwt("");
    setDraftTenant("");
  };

  return (
    <div className="flex min-h-screen bg-base-900 text-slate-100">
      <aside className="hidden w-64 flex-col border-r border-base-600 bg-base-800/80 p-6 lg:flex">
        <div className="mb-8">
          <p className="text-xs uppercase tracking-[0.5em] text-slate-400">QIMEM</p>
          <h1 className="mt-2 text-lg font-semibold">Playground</h1>
          <p className="mt-2 text-xs text-slate-400">Tenant-scoped crypto control plane</p>
        </div>
        <nav className="space-y-3 text-sm text-slate-300">
          {navItems.map((item) => (
            <a key={item.id} href={`#${item.id}`} className="block rounded-md px-3 py-2 hover:bg-base-700">
              {item.label}
            </a>
          ))}
        </nav>
        <div className="mt-auto pt-8 text-xs text-slate-500">
          <p>API Base</p>
          <p className="truncate font-mono text-[11px] text-slate-300">{API_BASE_URL}</p>
        </div>
      </aside>

      <main className="flex-1 p-6 lg:p-10">
        <div className="mb-8 flex flex-col gap-4 rounded-md border border-base-600 bg-base-800/80 p-6 shadow-panel">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.4em] text-slate-400">Security Control Plane</p>
              <h2 className="mt-2 text-2xl font-semibold">QIMEM Playground</h2>
              <p className="mt-2 text-sm text-slate-400">
                Live demonstrations of tenant-scoped encryption, hybrid PQ sessions, signing, and audit integrity.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200 hover:bg-base-700"
                onClick={() => setDevPanelOpen(true)}
              >
                Dev Access Panel
              </button>
              <button
                className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200 hover:bg-base-700"
                onClick={clearSensitive}
              >
                Clear Session
              </button>
            </div>
          </div>
          <div className="grid gap-4 text-sm md:grid-cols-3">
            <div>
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">JWT Status</p>
              <p className="mt-1 font-mono text-xs text-slate-200">{jwt ? "Loaded" : "Missing"}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Tenant ID</p>
              <p className="mt-1 font-mono text-xs text-slate-200">{tenantId || "Not set"}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Mock Mode</p>
              <p className="mt-1 font-mono text-xs text-slate-200">{mockMode ? "Enabled" : "Disabled"}</p>
            </div>
          </div>
        </div>

        <div className="space-y-8">
          <div id="encryption">
            <Panel
              title="Encryption Lab"
              description="Envelope encryption powered by /v1/kms/encrypt and /v1/kms/decrypt. All cryptography is handled by QIMEM."
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="space-y-4">
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Plaintext</label>
                  <textarea
                    className="min-h-[120px] w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={plaintext}
                    onChange={(event) => setPlaintext(event.target.value)}
                  />
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                      onClick={handleEncrypt}
                      disabled={!isReady}
                    >
                      Encrypt
                    </button>
                    <button
                      className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200"
                      onClick={handleDecrypt}
                      disabled={!isReady}
                    >
                      Decrypt
                    </button>
                  </div>
                  {encryptError && <JsonViewer data={encryptError} />}
                  {decryptError && <JsonViewer data={decryptError} />}
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Encrypt Response</p>
                    <JsonViewer data={encryptResponse} />
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Decrypted Plaintext</p>
                    <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-sm">
                      {decryptResponse ? fromBase64(decryptResponse.plaintext_b64) : "—"}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Decrypt Response</p>
                    <JsonViewer data={decryptResponse} />
                  </div>
                </div>
              </div>
            </Panel>
          </div>

          <div id="signing">
            <Panel
              title="Signing Lab"
              description="Server-side Ed25519 signing and verification. Keys never leave the backend unless you provide your own."
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="space-y-4">
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Message</label>
                  <textarea
                    className="min-h-[120px] w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={signMessage}
                    onChange={(event) => setSignMessage(event.target.value)}
                  />
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                      onClick={handleSign}
                      disabled={!isReady}
                    >
                      Sign
                    </button>
                    <button
                      className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200"
                      onClick={handleVerify}
                      disabled={!isReady}
                    >
                      Verify
                    </button>
                  </div>
                  {signError && <JsonViewer data={signError} />}
                  {verifyError && <JsonViewer data={verifyError} />}
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Signature Output</p>
                    <JsonViewer data={signResponse} />
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Verification Result</p>
                    <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-sm">
                      {verifyResponse ? (verifyResponse.valid ? "Valid" : "Invalid") : "—"}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Verify Response</p>
                    <JsonViewer data={verifyResponse} />
                  </div>
                </div>
              </div>
            </Panel>
          </div>

          <div id="pq">
            <Panel
              title="Post-Quantum Session"
              description="Hybrid session = classical X25519 + post-quantum Kyber combined through HKDF."
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="space-y-4">
                  <p className="text-xs text-slate-400">
                    Client key material is generated by the QIMEM API for demo safety. No browser crypto is used.
                  </p>
                  <button
                    className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                    onClick={handlePqSession}
                    disabled={!isReady}
                  >
                    Establish Session
                  </button>
                  {pqError && <JsonViewer data={pqError} />}
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Kyber Public Key</p>
                    <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-xs font-mono">
                      {pqKeypair?.public_key_b64 ?? "—"}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">X25519 Public Key</p>
                    <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-xs font-mono">
                      {pqX25519?.public_key_b64 ?? "—"}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Session Key (masked)</p>
                    <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-xs font-mono">
                      {maskSecret(pqSession?.session_key_b64)}
                    </div>
                  </div>
                  <JsonViewer data={pqSession} />
                </div>
              </div>
            </Panel>
          </div>

          <div id="self-destruct">
            <Panel
              title="Self-Destruct Encryption"
              description="Encrypt with a TTL. The backend enforces expiry on decryption."
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="space-y-4">
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Plaintext</label>
                  <textarea
                    className="min-h-[120px] w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={selfDestructText}
                    onChange={(event) => setSelfDestructText(event.target.value)}
                  />
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Passphrase</label>
                  <input
                    type="password"
                    className="w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={selfDestructPassphrase}
                    onChange={(event) => setSelfDestructPassphrase(event.target.value)}
                  />
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">TTL (seconds)</label>
                  <input
                    type="number"
                    min={5}
                    className="w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={selfDestructTtl}
                    onChange={(event) => setSelfDestructTtl(Number(event.target.value))}
                  />
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                      onClick={handleSelfDestructEncrypt}
                      disabled={!isReady}
                    >
                      Encrypt with TTL
                    </button>
                    <button
                      className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200"
                      onClick={handleSelfDestructDecrypt}
                      disabled={!isReady}
                    >
                      Attempt Decrypt
                    </button>
                  </div>
                  {selfDestructError && <JsonViewer data={selfDestructError} />}
                </div>
                <div className="space-y-4">
                  <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-xs text-slate-300">
                    <p className="uppercase tracking-[0.3em] text-slate-500">Expiration</p>
                    <p className="mt-2 text-sm">{formatTimestamp(countdown.expiresAt ?? undefined)}</p>
                    <p className="mt-2 text-xs text-slate-400">
                      Countdown: {countdown.remainingSeconds ?? "—"}s
                    </p>
                  </div>
                  <JsonViewer data={selfDestructEncrypt} />
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Decrypted Output</p>
                    <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-sm">
                      {selfDestructDecrypt ?? "—"}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Decrypt Response</p>
                    <JsonViewer data={selfDestructDecryptRaw} />
                  </div>
                </div>
              </div>
            </Panel>
          </div>

          <div id="isolation">
            <Panel
              title="Tenant Isolation Simulator"
              description="Attempt to decrypt Tenant A ciphertext while authenticated as Tenant A but using Tenant B header."
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="space-y-4">
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Tenant A (encrypt)</label>
                  <input
                    className="w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={tenantA}
                    onChange={(event) => setTenantA(event.target.value)}
                    placeholder="Use current tenant or paste Tenant A"
                  />
                  <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Tenant B (decrypt attempt)</label>
                  <input
                    className="w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                    value={tenantB}
                    onChange={(event) => setTenantB(event.target.value)}
                    placeholder="Paste Tenant B"
                  />
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                      onClick={handleIsolationEncrypt}
                      disabled={!isReady}
                    >
                      Encrypt Under Tenant A
                    </button>
                    <button
                      className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200"
                      onClick={handleIsolationDecrypt}
                      disabled={!isReady}
                    >
                      Attempt Decrypt as Tenant B
                    </button>
                  </div>
                  {isolationError && <JsonViewer data={isolationError} />}
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Encrypted Payload</p>
                    <JsonViewer data={isolationCipher} />
                  </div>
                  <div className="rounded-md border border-base-600 bg-base-900/70 p-3 text-sm">
                    {isolationStatus || "—"}
                  </div>
                </div>
              </div>
            </Panel>
          </div>

          <div id="audit">
            <Panel
              title="Audit Chain Viewer"
              description="Hash-chained audit logs. Client-side verification uses WebCrypto SHA-256 for demo-only integrity checks."
            >
              <div className="flex flex-wrap gap-2">
                <button
                  className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                  onClick={handleAuditRefresh}
                  disabled={!isReady}
                >
                  Refresh Audit Logs
                </button>
              </div>
              {auditError && <JsonViewer data={auditError} />}
              <div className="mt-4 space-y-4">
                {auditLogs.length === 0 ? (
                  <div className="rounded-md border border-dashed border-base-600 bg-base-700/50 p-3 text-xs text-slate-400">
                    No audit entries yet.
                  </div>
                ) : (
                  auditLogs.map((entry, index) => {
                    const isValid = auditVerification[entry.id];
                    return (
                      <div key={entry.id} className="rounded-md border border-base-600 bg-base-900/70 p-4">
                        <div className="flex items-center justify-between">
                          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">{entry.event_type}</p>
                          <span
                            className={`rounded-full px-2 py-1 text-[10px] uppercase tracking-[0.3em] ${
                              isValid === false ? "bg-red-500/20 text-red-300" : "bg-accent/20 text-accent"
                            }`}
                          >
                            {isValid === false ? "Mismatch" : "Verified"}
                          </span>
                        </div>
                        <div className="mt-3 grid gap-2 text-xs text-slate-300 md:grid-cols-2">
                          <div>
                            <p className="uppercase tracking-[0.3em] text-slate-500">Tenant</p>
                            <p className="mt-1 font-mono text-xs">{entry.tenant_id}</p>
                          </div>
                          <div>
                            <p className="uppercase tracking-[0.3em] text-slate-500">Timestamp</p>
                            <p className="mt-1 font-mono text-xs">{formatTimestamp(entry.created_at)}</p>
                          </div>
                          <div>
                            <p className="uppercase tracking-[0.3em] text-slate-500">Hash</p>
                            <p className="mt-1 font-mono text-xs break-all">{entry.event_hash_b64}</p>
                          </div>
                          <div>
                            <p className="uppercase tracking-[0.3em] text-slate-500">Prev Hash</p>
                            <p className="mt-1 font-mono text-xs break-all">{entry.prev_hash_b64 ?? "—"}</p>
                          </div>
                        </div>
                        {index < auditLogs.length - 1 && (
                          <div className="mt-4 h-6 border-l border-base-600" />
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </Panel>
          </div>
        </div>
      </main>

      <aside className="hidden w-80 border-l border-base-600 bg-base-800/70 p-6 xl:block">
        <h3 className="text-xs uppercase tracking-[0.4em] text-slate-400">Context</h3>
        <p className="mt-4 text-sm text-slate-300">
          QIMEM Playground mirrors production request flows. All cryptographic actions are executed by the Rust KMS
          service. This console never persists tokens or secrets to disk.
        </p>
        <div className="mt-6 rounded-md border border-base-600 bg-base-900/70 p-4 text-xs text-slate-400">
          <p className="uppercase tracking-[0.3em]">Security Notes</p>
          <ul className="mt-3 list-disc space-y-2 pl-4">
            <li>JWT and tenant identifiers are held only in memory.</li>
            <li>Audit chain verification is client-side and demo-only.</li>
            <li>All KMS responses are shown verbatim for inspection.</li>
            <li>Self-destruct timers visualize expiry but backend enforces it.</li>
          </ul>
        </div>
      </aside>

      {devPanelOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-xl rounded-md border border-base-600 bg-base-800 p-6 shadow-panel">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold uppercase tracking-[0.3em] text-slate-300">Dev Access Panel</h3>
              <button
                className="text-xs uppercase tracking-[0.2em] text-slate-400 hover:text-slate-200"
                onClick={() => setDevPanelOpen(false)}
              >
                Close
              </button>
            </div>
            <div className="mt-4 space-y-4 text-sm">
              <div>
                <label className="text-xs uppercase tracking-[0.3em] text-slate-400">JWT (in-memory)</label>
                <input
                  type="password"
                  className="mt-2 w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                  value={draftJwt}
                  onChange={(event) => setDraftJwt(event.target.value)}
                  placeholder="Bearer token"
                />
              </div>
              <div>
                <label className="text-xs uppercase tracking-[0.3em] text-slate-400">Tenant ID</label>
                <input
                  className="mt-2 w-full rounded-md border border-base-600 bg-base-700/60 p-3 text-sm"
                  value={draftTenant}
                  onChange={(event) => setDraftTenant(event.target.value)}
                  placeholder="UUID"
                />
              </div>
              <label className="flex items-center gap-3 text-xs uppercase tracking-[0.3em] text-slate-400">
                <input
                  type="checkbox"
                  checked={mockMode}
                  onChange={(event) => setMockMode(event.target.checked)}
                />
                Mock Mode (optional)
              </label>
              <div className="flex flex-wrap gap-2">
                <button
                  className="rounded-md border border-accent px-4 py-2 text-xs uppercase tracking-[0.2em] text-accent"
                  onClick={() => {
                    setJwt(draftJwt);
                    setTenantId(draftTenant);
                    setDevPanelOpen(false);
                  }}
                >
                  Save Session
                </button>
                <button
                  className="rounded-md border border-base-600 px-4 py-2 text-xs uppercase tracking-[0.2em] text-slate-200"
                  onClick={clearSensitive}
                >
                  Clear
                </button>
              </div>
              <p className="text-xs text-slate-500">
                Tokens are stored in memory only and are cleared when the page refreshes or the session is cleared.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
