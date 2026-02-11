"use client";

import { useEffect, useMemo, useState } from "react";
import { AuditChainViewer } from "./components/AuditChainViewer";
import { DevAccessPanel } from "./components/DevAccessPanel";
import { EncryptionLab } from "./components/EncryptionLab";
import { Header } from "./components/Header";
import { PQSessionDemo } from "./components/PQSessionDemo";
import { SelfDestructDemo } from "./components/SelfDestructDemo";
import { Sidebar } from "./components/Sidebar";
import { SigningLab } from "./components/SigningLab";
import { TenantIsolationSimulator } from "./components/TenantIsolationSimulator";
import { ApiResponseViewer, Panel } from "./components/ui";
import { ApiError, AuditEntry, EncryptResponse, PQKeypair, PQSessionResponse, SelfDestructResponse, SignResponse, createQimemClient } from "./lib/qimemClient";

const API_BASE_URL = process.env.NEXT_PUBLIC_QIMEM_API_BASE_URL ?? "http://localhost:8080";

const normalizeError = (error: unknown): ApiError => {
  if (typeof error === "object" && error && "status" in error && "message" in error) {
    return error as ApiError;
  }
  return { status: 500, message: "Unexpected error", details: error };
};

export default function Home() {
  const [jwt, setJwt] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [error, setError] = useState<ApiError | null>(null);

  const client = useMemo(() => createQimemClient({ baseUrl: API_BASE_URL, getCredentials: () => ({ jwt, tenantId }) }), [jwt, tenantId]);

  const [plaintext, setPlaintext] = useState("");
  const [encrypted, setEncrypted] = useState<EncryptResponse | null>(null);
  const [decrypted, setDecrypted] = useState("");

  const [message, setMessage] = useState("");
  const [signResult, setSignResult] = useState<SignResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);

  const [pqKeypair, setPqKeypair] = useState<PQKeypair | null>(null);
  const [pqSession, setPqSession] = useState<PQSessionResponse | null>(null);

  const [ttlPayload, setTtlPayload] = useState("");
  const [ttl, setTtl] = useState(60);
  const [selfDestruct, setSelfDestruct] = useState<SelfDestructResponse | null>(null);
  const [selfDestructDecryptResult, setSelfDestructDecryptResult] = useState("");
  const [countdown, setCountdown] = useState<number | null>(null);

  const [activeTenant, setActiveTenant] = useState("Tenant A");
  const [tenantStatus, setTenantStatus] = useState("");

  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [verification, setVerification] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!selfDestruct?.expires_at) {
      setCountdown(null);
      return;
    }
    const timer = window.setInterval(() => {
      const left = Math.max(0, Math.ceil(selfDestruct.expires_at! - Date.now() / 1000));
      setCountdown(left);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [selfDestruct]);

  const withError = async (fn: () => Promise<void>) => {
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(normalizeError(e));
    }
  };

  const verifyAudit = async () => {
    const map: Record<string, boolean> = {};
    for (const entry of audit) {
      const payload = JSON.stringify({ tenant_id: entry.tenant_id, event_type: entry.event_type, metadata: entry.metadata });
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
      const hash = btoa(String.fromCharCode(...new Uint8Array(digest)));
      map[entry.id] = hash === entry.event_hash_b64;
    }
    setVerification(map);
  };

  return (
    <div className="min-h-screen bg-base-bg text-base-text">
      <Sidebar />
      <main className="ml-64 p-6">
        <div className="mx-auto max-w-5xl space-y-4">
          <Header />
          <DevAccessPanel jwt={jwt} tenantId={tenantId} setJwt={setJwt} setTenantId={setTenantId} />
          {error && <ApiResponseViewer data={error} />}

          <EncryptionLab
            plaintext={plaintext}
            setPlaintext={setPlaintext}
            encrypted={encrypted}
            decrypted={decrypted}
            onEncrypt={() => withError(async () => setEncrypted(await client.encrypt(plaintext)))}
            onDecrypt={() => withError(async () => { if (!encrypted) return; setDecrypted(await client.decrypt(encrypted)); })}
            error={null}
          />

          <SigningLab
            message={message}
            setMessage={setMessage}
            signResult={signResult}
            verifyResult={verifyResult}
            onSign={() => withError(async () => setSignResult(await client.sign(message)))}
            onVerify={() => withError(async () => { if (!signResult) return; setVerifyResult(await client.verify(signResult.signature_b64, message, signResult.public_key_b64)); })}
            error={null}
          />

          <PQSessionDemo
            keypair={pqKeypair}
            session={pqSession}
            onKeypair={() => withError(async () => setPqKeypair(await client.pqKeypair()))}
            onSession={() => withError(async () => { if (!pqKeypair) return; setPqSession(await client.pqSession(pqKeypair.public_key_b64)); })}
            error={null}
          />

          <SelfDestructDemo
            payload={ttlPayload}
            setPayload={setTtlPayload}
            ttl={ttl}
            setTtl={setTtl}
            encrypted={selfDestruct}
            decryptResult={selfDestructDecryptResult}
            countdown={countdown}
            onEncrypt={() => withError(async () => setSelfDestruct(await client.selfDestruct(ttlPayload, ttl)))}
            onDecrypt={() =>
              withError(async () => {
                if (!selfDestruct) return;
                const out = await client.selfDestructDecrypt(selfDestruct.ciphertext_b64);
                setSelfDestructDecryptResult(out.plaintext_b64 ? "Decrypted (base64 response)." : "No plaintext");
              })
            }
            error={null}
          />

          <TenantIsolationSimulator
            activeTenant={activeTenant}
            setActiveTenant={setActiveTenant}
            status={tenantStatus}
            onRun={() =>
              withError(async () => {
                const encryptedA = await client.encrypt("tenant-isolation-test");
                const tenantBClient = createQimemClient({
                  baseUrl: API_BASE_URL,
                  getCredentials: () => ({ jwt, tenantId: activeTenant === "Tenant A" ? `${tenantId}-B` : `${tenantId}-A` }),
                });
                await tenantBClient.decrypt(encryptedA);
                setTenantStatus("Unexpected success; inspect tenant settings.");
              })
            }
            error={null}
          />

          <AuditChainViewer
            entries={audit}
            verification={verification}
            onRefresh={() => withError(async () => setAudit(await client.getAuditChain()))}
            onVerify={() => withError(async () => verifyAudit())}
            error={null}
          />

          <Panel title="Help & Info">
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
              <li>Each panel maps directly to a QIMEM API call path and displays live JSON responses.</li>
              <li>JWT and tenant ID live in memory only; this app does not use localStorage/sessionStorage.</li>
              <li>Decrypted plaintext is rendered to UI only and not logged/persisted.</li>
              <li>Mock Provider Reverses Prompt for Safe Demos: use only for synthetic demonstration workflows.</li>
            </ul>
          </Panel>
        </div>
      </main>
    </div>
  );
}
