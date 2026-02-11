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
  const [globalError, setGlobalError] = useState<ApiError | null>(null);

  const client = useMemo(() => createQimemClient({ baseUrl: API_BASE_URL, getCredentials: () => ({ jwt, tenantId }) }), [jwt, tenantId]);

  const [plaintext, setPlaintext] = useState("");
  const [encrypted, setEncrypted] = useState<EncryptResponse | null>(null);
  const [decrypted, setDecrypted] = useState("");
  const [encryptionError, setEncryptionError] = useState<ApiError | null>(null);

  const [message, setMessage] = useState("");
  const [signResult, setSignResult] = useState<SignResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [signError, setSignError] = useState<ApiError | null>(null);

  const [pqKeypair, setPqKeypair] = useState<PQKeypair | null>(null);
  const [pqSession, setPqSession] = useState<PQSessionResponse | null>(null);
  const [pqError, setPqError] = useState<ApiError | null>(null);

  const [ttlPayload, setTtlPayload] = useState("");
  const [ttl, setTtl] = useState(60);
  const [selfDestruct, setSelfDestruct] = useState<SelfDestructResponse | null>(null);
  const [selfDestructDecryptResult, setSelfDestructDecryptResult] = useState("");
  const [countdown, setCountdown] = useState<number | null>(null);
  const [selfDestructError, setSelfDestructError] = useState<ApiError | null>(null);

  const [activeTenant, setActiveTenant] = useState("Tenant A");
  const [tenantStatus, setTenantStatus] = useState("");
  const [tenantError, setTenantError] = useState<ApiError | null>(null);

  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [verification, setVerification] = useState<Record<string, boolean>>({});
  const [auditError, setAuditError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (!selfDestruct?.expires_at) {
      setCountdown(null);
      return;
    }
    const expiresAt = selfDestruct.expires_at;
    if (!expiresAt) return;
    const timer = window.setInterval(() => {
      const left = Math.max(0, Math.ceil(expiresAt - Date.now() / 1000));
      setCountdown(left);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [selfDestruct]);

  const verifyAudit = async () => {
    const map: Record<string, boolean> = {};
    for (const entry of audit) {
      const payload = {
        tenant_id: entry.tenant_id,
        event_type: entry.event_type,
        metadata: entry.metadata,
        prev_hash: entry.prev_hash_b64 ?? null,
      };
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(payload)));
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
          {globalError && <ApiResponseViewer data={globalError} />}

          <EncryptionLab
            plaintext={plaintext}
            setPlaintext={setPlaintext}
            encrypted={encrypted}
            decrypted={decrypted}
            onEncrypt={async () => {
              setEncryptionError(null);
              try {
                setEncrypted(await client.encrypt(plaintext));
                setDecrypted("");
              } catch (error) {
                setEncryptionError(normalizeError(error));
              }
            }}
            onDecrypt={async () => {
              if (!encrypted) return;
              setEncryptionError(null);
              try {
                setDecrypted(await client.decrypt(encrypted));
              } catch (error) {
                setEncryptionError(normalizeError(error));
              }
            }}
            error={encryptionError}
          />

          <SigningLab
            message={message}
            setMessage={setMessage}
            signResult={signResult}
            verifyResult={verifyResult}
            onSign={async () => {
              setSignError(null);
              try {
                setSignResult(await client.sign(message));
                setVerifyResult(null);
              } catch (error) {
                setSignError(normalizeError(error));
              }
            }}
            onVerify={async () => {
              if (!signResult) return;
              setSignError(null);
              try {
                setVerifyResult(await client.verify(signResult.signature_b64, message, signResult.public_key_b64));
              } catch (error) {
                setSignError(normalizeError(error));
              }
            }}
            error={signError}
          />

          <PQSessionDemo
            keypair={pqKeypair}
            session={pqSession}
            onKeypair={async () => {
              setPqError(null);
              try {
                setPqKeypair(await client.pqKeypair());
              } catch (error) {
                setPqError(normalizeError(error));
              }
            }}
            onSession={async () => {
              if (!pqKeypair) return;
              setPqError(null);
              try {
                setPqSession(await client.pqSession(pqKeypair.public_key_b64));
              } catch (error) {
                setPqError(normalizeError(error));
              }
            }}
            error={pqError}
          />

          <SelfDestructDemo
            payload={ttlPayload}
            setPayload={setTtlPayload}
            ttl={ttl}
            setTtl={setTtl}
            encrypted={selfDestruct}
            decryptResult={selfDestructDecryptResult}
            countdown={countdown}
            onEncrypt={async () => {
              setSelfDestructError(null);
              try {
                setSelfDestruct(await client.selfDestruct(ttlPayload, ttl));
                setSelfDestructDecryptResult("");
              } catch (error) {
                setSelfDestructError(normalizeError(error));
              }
            }}
            onDecrypt={async () => {
              if (!selfDestruct) return;
              setSelfDestructError(null);
              try {
                await client.selfDestructDecrypt(selfDestruct.ciphertext_b64);
                setSelfDestructDecryptResult("Decrypt accepted by API (payload intentionally not persisted).");
              } catch (error) {
                const normalized = normalizeError(error);
                setSelfDestructError(normalized);
                setSelfDestructDecryptResult(`Decrypt rejected by API (${normalized.status}).`);
              }
            }}
            error={selfDestructError}
          />

          <TenantIsolationSimulator
            activeTenant={activeTenant}
            setActiveTenant={setActiveTenant}
            status={tenantStatus}
            onRun={async () => {
              setTenantError(null);
              setTenantStatus("");
              try {
                const encryptedA = await client.encrypt("tenant-isolation-test");
                const tenantVariant = activeTenant === "Tenant A" ? "tenant-b" : "tenant-a";
                const tenantBClient = createQimemClient({
                  baseUrl: API_BASE_URL,
                  getCredentials: () => ({ jwt, tenantId: `${tenantId}-${tenantVariant}` }),
                });
                await tenantBClient.decrypt(encryptedA);
                setTenantStatus("Unexpected decrypt success. Check API tenant enforcement configuration.");
              } catch (error) {
                const normalized = normalizeError(error);
                setTenantError(normalized);
                setTenantStatus(`Expected rejection confirmed (${normalized.status}).`);
              }
            }}
            error={tenantError}
          />

          <AuditChainViewer
            entries={audit}
            verification={verification}
            onRefresh={async () => {
              setAuditError(null);
              try {
                setAudit(await client.getAuditChain());
              } catch (error) {
                setAuditError(normalizeError(error));
              }
            }}
            onVerify={async () => {
              setAuditError(null);
              try {
                await verifyAudit();
              } catch (error) {
                setAuditError(normalizeError(error));
              }
            }}
            error={auditError}
          />

          <Panel title="Help & Info">
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
              <li>All cryptographic operations are performed by the QIMEM API using live endpoints.</li>
              <li>JWT and tenant ID are in-memory only and are never persisted to browser storage.</li>
              <li>Decrypted plaintext is only displayed in-session and never written to logs or local storage.</li>
              <li>Audit verification is a demo integrity check that recomputes a client-side SHA-256 chain.</li>
              <li>Mock Provider Reverses Prompt for Safe Demos: only for synthetic safe demonstrations.</li>
            </ul>
          </Panel>
        </div>
      </main>
    </div>
  );
}
