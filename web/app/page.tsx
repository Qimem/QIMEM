"use client";

import { useMemo, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

function encodeBase64(input: string): string {
  return btoa(new TextEncoder().encode(input).reduce((data, byte) => data + String.fromCharCode(byte), ""));
}

export default function Home() {
  const [tenantId, setTenantId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [prompt, setPrompt] = useState("Summarize the threat model.");
  const [encryptedBlob, setEncryptedBlob] = useState({
    ciphertext: "",
    wrappedDek: "",
    nonce: "",
    keyVersion: 0,
    algorithm: "chacha20poly1305",
  });
  const [gatewayResponse, setGatewayResponse] = useState("");
  const [auditLog, setAuditLog] = useState("");
  const [status, setStatus] = useState("");

  const isReady = useMemo(() => apiKey.length > 0 && tenantId.length > 0, [apiKey, tenantId]);
  const isDev = process.env.NODE_ENV !== "production";

  const baseHeaders = useMemo(() => {
    return {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "X-Tenant-ID": tenantId,
    };
  }, [apiKey, tenantId]);

  const handleCreateTenant = async () => {
    setStatus("");
    const response = await fetch(`${API_BASE}/v1/kms/tenants`, {
      method: "POST",
      headers: baseHeaders,
      body: JSON.stringify({ name: "control-plane" }),
    });
    if (!response.ok) {
      setStatus(`Create tenant failed (${response.status}).`);
      return;
    }
    const data = await response.json();
    setTenantId(data.tenant_id);
    setStatus("Tenant created.");
  };

  const handleSecurePrompt = async () => {
    setStatus("");
    const encryptResponse = await fetch(`${API_BASE}/v1/kms/encrypt`, {
      method: "POST",
      headers: baseHeaders,
      body: JSON.stringify({ plaintext_b64: encodeBase64(prompt) }),
    });
    if (!encryptResponse.ok) {
      setStatus(`Encrypt failed (${encryptResponse.status}).`);
      return;
    }
    const encrypted = await encryptResponse.json();
    setEncryptedBlob({
      ciphertext: encrypted.ciphertext_b64,
      wrappedDek: encrypted.wrapped_dek_b64,
      nonce: encrypted.nonce_b64,
      keyVersion: encrypted.key_version,
      algorithm: encrypted.algorithm,
    });
    const gatewayResponse = await fetch(`${API_BASE}/v1/gateway/proxy`, {
      method: "POST",
      headers: baseHeaders,
      body: JSON.stringify({
        provider: "mock",
        encrypted_payload: encrypted.ciphertext_b64,
        wrapped_dek: encrypted.wrapped_dek_b64,
        key_version: encrypted.key_version,
        provider_config: {},
        nonce: encrypted.nonce_b64,
        algorithm: encrypted.algorithm,
      }),
    });
    if (!gatewayResponse.ok) {
      setStatus(`Gateway failed (${gatewayResponse.status}).`);
      return;
    }
    const result = await gatewayResponse.json();
    setGatewayResponse(JSON.stringify(result, null, 2));
    setAuditLog("decrypt • hash chain advanced");
  };

  return (
    <main className="page">
      <div className="container">
        <header className="space-y-2">
          <p className="text-xs uppercase tracking-[0.5em] text-neutral-400">
            QIMEM CONTROL PLANE
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-neutral-100">
            Security Control Plane
          </h1>
          <p className="text-sm text-neutral-500">
            Tenant-scoped encryption lifecycle with audit integrity and hybrid PQ readiness.
          </p>
        </header>

        <section className="section-grid">
          <div className="panel">
            <h2 className="panel-title">Tenant Dashboard</h2>
            <div className="panel-body">
              <p>Tenant ID: {tenantId || "unassigned"}</p>
              <p>Master Key Version: {encryptedBlob.keyVersion || "-"}</p>
              <p>PQ Status: ACTIVE</p>
              <p>Last Rotation: 14m ago</p>
              <button className="btn" onClick={handleCreateTenant} disabled={!apiKey}>
                Create Tenant
              </button>
            </div>
          </div>
          <div className="panel">
            <h2 className="panel-title">Vault Manager</h2>
            <div className="panel-body">
              <p>Stored API Keys: 2</p>
              <p>Last Access: 3m ago</p>
              <button className="btn">Create Scoped Token</button>
            </div>
          </div>
          <div className="panel">
            <h2 className="panel-title">Crypto Policy Panel</h2>
            <div className="panel-body">
              <p>Algorithm: ChaCha20-Poly1305</p>
              <p>Hybrid PQ: Enabled</p>
              <p>Policy Version: 1</p>
              <p>Rotation History: 3 events</p>
            </div>
          </div>
        </section>

        <section className="panel">
          <h2 className="panel-title">Secure AI Playground</h2>
          <div className="panel-body split">
            <div className="space-y-3">
              <label className="label">
                API Key (JWT)
                <input
                  className="input"
                  value={apiKey}
                  onChange={(event) => setApiKey(event.target.value)}
                  placeholder="Bearer token"
                />
              </label>
              <label className="label">
                Tenant ID
                <input
                  className="input"
                  value={tenantId}
                  onChange={(event) => setTenantId(event.target.value)}
                  placeholder="UUID"
                />
              </label>
              <label className="label">
                Prompt
                <textarea
                  className="input h-32"
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                />
              </label>
              <button className="btn" onClick={handleSecurePrompt} disabled={!isReady}>
                Encrypt + Send (Server-Side)
              </button>
              {status && <p className="text-xs text-neutral-500">{status}</p>}
            </div>
            <div className="space-y-3">
              <div className="panel-sub">
                <p>Ciphertext</p>
                <code>{encryptedBlob.ciphertext || "pending"}</code>
              </div>
              <div className="panel-sub">
                <p>Wrapped DEK</p>
                <code>{encryptedBlob.wrappedDek || "pending"}</code>
              </div>
              <div className="panel-sub">
                <p>Nonce / Algorithm</p>
                <code>
                  {encryptedBlob.nonce || "pending"} • {encryptedBlob.algorithm}
                </code>
              </div>
              <div className="panel-sub">
                <p>Provider Response</p>
                <code>{gatewayResponse || "awaiting response"}</code>
              </div>
              <div className="panel-sub">
                <p>Audit Log</p>
                <code>{auditLog || "no events"}</code>
              </div>
            </div>
          </div>
        </section>

        <section className="panel">
          <h2 className="panel-title">Audit Log Viewer</h2>
          <div className="panel-body">
            <div className="grid gap-3 md:grid-cols-3">
              <div className="panel-sub">
                <p>Event</p>
                <code>decrypt</code>
              </div>
              <div className="panel-sub">
                <p>Hash</p>
                <code>0x9b13...e0c2</code>
              </div>
              <div className="panel-sub">
                <p>Prev Hash</p>
                <code>0x7a02...19ff</code>
              </div>
            </div>
            <button className="btn mt-4">Verify Chain</button>
          </div>
        </section>

        {isDev && (
          <section className="panel">
            <h2 className="panel-title">Dev Panel</h2>
            <div className="panel-body">
              <p>API Base: {API_BASE}</p>
              <p>Tenant override and debug toggles are disabled in production.</p>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
