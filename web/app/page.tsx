"use client";

import { useEffect, useState } from "react";

const defaultBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080";

async function callApi<T>(
  path: string,
  method: "POST" | "GET",
  body: Record<string, unknown> | null,
  token: string | null,
): Promise<T> {
  const response = await fetch(`${defaultBaseUrl}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error || "Request failed");
  }
  return response.json();
}

export default function Home() {
  const [token, setToken] = useState<string | null>(null);
  const [tokenInput, setTokenInput] = useState("");
  const [keyResult, setKeyResult] = useState("");
  const [cryptoResult, setCryptoResult] = useState("");
  const [signResult, setSignResult] = useState("");
  const [totpResult, setTotpResult] = useState("");
  const [pqResult, setPqResult] = useState("");

  useEffect(() => {
    const stored = window.localStorage.getItem("qimem-token");
    if (stored) {
      setToken(stored);
      setTokenInput(stored);
    }
  }, []);

  const persistToken = () => {
    window.localStorage.setItem("qimem-token", tokenInput);
    setToken(tokenInput);
  };

  const clearToken = () => {
    window.localStorage.removeItem("qimem-token");
    setToken(null);
    setTokenInput("");
  };

  return (
    <main>
      <header>
        <div>
          <h1>QIMEM COMMAND</h1>
          <p>Zero-trust cryptography console · monochrome deployment profile</p>
        </div>
        <span className="badge">PUBLIC BETA</span>
      </header>

      <section>
        <h2>Better Auth Access Token</h2>
        <p>Paste the Better Auth-issued JWT. Requests are rejected without it.</p>
        <label htmlFor="token">Bearer Token</label>
        <textarea
          id="token"
          rows={3}
          value={tokenInput}
          onChange={(event) => setTokenInput(event.target.value)}
          placeholder="eyJhbGciOiJI..."
        />
        <div style={{ display: "flex", gap: 12 }}>
          <button onClick={persistToken}>Arm Session</button>
          <button onClick={clearToken}>Purge Token</button>
        </div>
        <div className="output" style={{ marginTop: 16 }}>
          Active token: {token ? "loaded" : "missing"}
        </div>
      </section>

      <div className="grid">
        <section>
          <h2>Hardware-Bound Key Derivation</h2>
          <label>Password</label>
          <input id="password" type="password" placeholder="Enter passphrase" />
          <label>Salt Phrase</label>
          <input id="salt" placeholder="Optional salt" />
          <label>Device Fingerprint</label>
          <input id="device" placeholder="Hardware fingerprint" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  password: (document.getElementById("password") as HTMLInputElement).value,
                  salt_phrase: (document.getElementById("salt") as HTMLInputElement).value || null,
                  device_fingerprint: (document.getElementById("device") as HTMLInputElement).value || null,
                };
                const response = await callApi<{ key_b64: string; salt_b64: string }>(
                  "/v1/derive-key",
                  "POST",
                  payload,
                  token,
                );
                setKeyResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setKeyResult((error as Error).message);
              }
            }}
          >
            Derive Key
          </button>
          <div className="output">{keyResult}</div>
        </section>

        <section>
          <h2>Self-Destruct Encryption</h2>
          <label>Plaintext (base64)</label>
          <textarea id="plaintext" rows={3} placeholder="c2VjdXJlIG1lc3NhZ2U=" />
          <label>Key (base64)</label>
          <textarea id="key" rows={2} placeholder="32-byte key" />
          <label>Expires In (seconds)</label>
          <input id="expires" placeholder="3600" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  plaintext_b64: (document.getElementById("plaintext") as HTMLTextAreaElement).value,
                  key_b64: (document.getElementById("key") as HTMLTextAreaElement).value,
                  expires_in_seconds: Number((document.getElementById("expires") as HTMLInputElement).value) || null,
                };
                const response = await callApi<{ ciphertext_b64: string; expires_at: number | null }>(
                  "/v1/encrypt",
                  "POST",
                  payload,
                  token,
                );
                setCryptoResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setCryptoResult((error as Error).message);
              }
            }}
          >
            Encrypt
          </button>
          <button
            onClick={async () => {
              try {
                const payload = {
                  ciphertext_b64: (document.getElementById("ciphertext") as HTMLTextAreaElement).value,
                  key_b64: (document.getElementById("key") as HTMLTextAreaElement).value,
                };
                const response = await callApi<{ plaintext_b64: string; expires_at: number | null }>(
                  "/v1/decrypt",
                  "POST",
                  payload,
                  token,
                );
                setCryptoResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setCryptoResult((error as Error).message);
              }
            }}
          >
            Decrypt
          </button>
          <label>Ciphertext (base64)</label>
          <textarea id="ciphertext" rows={3} placeholder="Paste ciphertext" />
          <div className="output">{cryptoResult}</div>
        </section>

        <section>
          <h2>Signing & Verification</h2>
          <label>Message (base64)</label>
          <textarea id="sign-message" rows={2} placeholder="bWVzc2FnZQ==" />
          <label>Secret Key (base64)</label>
          <textarea id="sign-secret" rows={2} placeholder="32-byte key" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  message_b64: (document.getElementById("sign-message") as HTMLTextAreaElement).value,
                  secret_key_b64: (document.getElementById("sign-secret") as HTMLTextAreaElement).value,
                };
                const response = await callApi<{ signature_b64: string }>(
                  "/v1/sign",
                  "POST",
                  payload,
                  token,
                );
                setSignResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setSignResult((error as Error).message);
              }
            }}
          >
            Sign
          </button>
          <label>Public Key (base64)</label>
          <textarea id="verify-public" rows={2} placeholder="Public key" />
          <label>Signature (base64)</label>
          <textarea id="verify-signature" rows={2} placeholder="Signature" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  message_b64: (document.getElementById("sign-message") as HTMLTextAreaElement).value,
                  public_key_b64: (document.getElementById("verify-public") as HTMLTextAreaElement).value,
                  signature_b64: (document.getElementById("verify-signature") as HTMLTextAreaElement).value,
                };
                const response = await callApi<{ valid: boolean }>(
                  "/v1/verify",
                  "POST",
                  payload,
                  token,
                );
                setSignResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setSignResult((error as Error).message);
              }
            }}
          >
            Verify
          </button>
          <div className="output">{signResult}</div>
        </section>

        <section>
          <h2>TOTP / Zero-Trust MFA</h2>
          <button
            onClick={async () => {
              try {
                const response = await callApi<{ secret_b64: string }>(
                  "/v1/totp/secret",
                  "POST",
                  {},
                  token,
                );
                setTotpResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setTotpResult((error as Error).message);
              }
            }}
          >
            Generate Secret
          </button>
          <label>Secret (base64)</label>
          <input id="totp-secret" placeholder="Paste secret" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  secret_b64: (document.getElementById("totp-secret") as HTMLInputElement).value,
                };
                const response = await callApi<{ code: string }>(
                  "/v1/totp/code",
                  "POST",
                  payload,
                  token,
                );
                setTotpResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setTotpResult((error as Error).message);
              }
            }}
          >
            Generate Code
          </button>
          <label>Code</label>
          <input id="totp-code" placeholder="123456" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  secret_b64: (document.getElementById("totp-secret") as HTMLInputElement).value,
                  code: (document.getElementById("totp-code") as HTMLInputElement).value,
                };
                const response = await callApi<{ valid: boolean }>(
                  "/v1/totp/verify",
                  "POST",
                  payload,
                  token,
                );
                setTotpResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setTotpResult((error as Error).message);
              }
            }}
          >
            Verify Code
          </button>
          <div className="output">{totpResult}</div>
        </section>

        <section>
          <h2>Post-Quantum Session</h2>
          <button
            onClick={async () => {
              try {
                const response = await callApi<{ public_key_b64: string; secret_key_b64: string }>(
                  "/v1/pq/keypair",
                  "POST",
                  {},
                  token,
                );
                setPqResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setPqResult((error as Error).message);
              }
            }}
          >
            Generate Kyber Keypair
          </button>
          <label>Public Key (base64)</label>
          <textarea id="pq-public" rows={2} placeholder="Paste public key" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  public_key_b64: (document.getElementById("pq-public") as HTMLTextAreaElement).value,
                };
                const response = await callApi<{ ciphertext_b64: string; shared_secret_b64: string }>(
                  "/v1/pq/encapsulate",
                  "POST",
                  payload,
                  token,
                );
                setPqResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setPqResult((error as Error).message);
              }
            }}
          >
            Encapsulate
          </button>
          <label>Secret Key (base64)</label>
          <textarea id="pq-secret" rows={2} placeholder="Paste secret key" />
          <label>Ciphertext (base64)</label>
          <textarea id="pq-ciphertext" rows={2} placeholder="Paste ciphertext" />
          <button
            onClick={async () => {
              try {
                const payload = {
                  secret_key_b64: (document.getElementById("pq-secret") as HTMLTextAreaElement).value,
                  ciphertext_b64: (document.getElementById("pq-ciphertext") as HTMLTextAreaElement).value,
                };
                const response = await callApi<{ shared_secret_b64: string }>(
                  "/v1/pq/decapsulate",
                  "POST",
                  payload,
                  token,
                );
                setPqResult(JSON.stringify(response, null, 2));
              } catch (error) {
                setPqResult((error as Error).message);
              }
            }}
          >
            Decapsulate
          </button>
          <div className="output">{pqResult}</div>
        </section>
      </div>
    </main>
  );
}
