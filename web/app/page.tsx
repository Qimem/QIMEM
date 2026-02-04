"use client";

import { useEffect, useMemo, useState } from "react";
import nacl from "tweetnacl";
import { argon2id } from "@noble/hashes/argon2";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";

const APP_VERSION = "0.6.0-beta";
const CHANGELOG = [
  "Client-only crypto operations (no server secrets)",
  "Tabbed console with key management + PQ sandbox",
  "Vercel-ready web deployment",
];

const DEMO_MESSAGE = "When in doubt, verify. When certain, verify again.";

const tabs = [
  "Encryption",
  "Self-Destruct",
  "Signing",
  "TOTP",
  "Post-Quantum",
  "Keys",
] as const;

type Tab = (typeof tabs)[number];

type KeyRecord = {
  id: string;
  name: string;
  type: "symmetric" | "signing" | "asymmetric" | "pq";
  createdAt: string;
  material: Record<string, string>;
};

type Status = {
  tone: "idle" | "success" | "error" | "warning";
  message: string;
};

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const statusColor = {
  idle: "#9b9b9b",
  success: "#d9d9d9",
  warning: "#c4c4c4",
  error: "#ffb3b3",
};

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function base64ToBytes(data: string): Uint8Array {
  const normalized = data.replace(/\s+/g, "");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  bytes.forEach((byte) => {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  });
  if (bits > 0) {
    output += base32Alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input: string): Uint8Array {
  const cleaned = input.replace(/=+$/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const char of cleaned) {
    const index = base32Alphabet.indexOf(char);
    if (index === -1) {
      continue;
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function deriveKeyPBKDF2(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textToBytes(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 210_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

async function deriveKeyArgon2(password: string, salt: Uint8Array): Promise<Uint8Array> {
  return argon2id(textToBytes(password), salt, { t: 3, m: 65536, p: 1, dkLen: 32 });
}

async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  method: "PBKDF2" | "Argon2id",
): Promise<Uint8Array> {
  return method === "PBKDF2" ? deriveKeyPBKDF2(password, salt) : deriveKeyArgon2(password, salt);
}

async function encryptAesGcm(keyBytes: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const iv = randomBytes(12);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, message);
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);
  return result;
}

async function decryptAesGcm(keyBytes: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  const iv = payload.slice(0, 12);
  const ciphertext = payload.slice(12);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plaintext);
}

function saveKeys(keys: KeyRecord[]) {
  localStorage.setItem("qimem.keys", JSON.stringify(keys));
}

function loadKeys(): KeyRecord[] {
  const raw = localStorage.getItem("qimem.keys");
  if (!raw) return [];
  try {
    return JSON.parse(raw) as KeyRecord[];
  } catch {
    return [];
  }
}

async function copyWithWarning(label: string, value: string, setStatus: (s: Status) => void) {
  const confirmed = window.confirm(
    `Copy ${label}? Clipboard history can expose sensitive data.`,
  );
  if (!confirmed) return;
  await navigator.clipboard.writeText(value);
  setStatus({ tone: "success", message: `${label} copied to clipboard.` });
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<Tab>("Encryption");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [keys, setKeys] = useState<KeyRecord[]>([]);

  const [status, setStatus] = useState<Status>({
    tone: "idle",
    message: "All operations run locally in your browser.",
  });

  const [password, setPassword] = useState("");
  const [salt, setSalt] = useState(bytesToBase64(randomBytes(16)));
  const [kdfMethod, setKdfMethod] = useState<"PBKDF2" | "Argon2id">("Argon2id");
  const [plaintext, setPlaintext] = useState(DEMO_MESSAGE);
  const [derivedKey, setDerivedKey] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [decryptedText, setDecryptedText] = useState("");

  const [ttlSeconds, setTtlSeconds] = useState("3600");
  const [selfDestructPayload, setSelfDestructPayload] = useState("");
  const [ttlCountdown, setTtlCountdown] = useState<string | null>(null);

  const [signingKeypair, setSigningKeypair] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [signature, setSignature] = useState("");
  const [verificationResult, setVerificationResult] = useState<Status>({ tone: "idle", message: "" });

  const [totpSecret, setTotpSecret] = useState(base32Encode(randomBytes(20)));
  const [totpCode, setTotpCode] = useState("");

  const [pqKeypair, setPqKeypair] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [pqEncap, setPqEncap] = useState<{ ciphertext: string; sharedSecret: string } | null>(null);
  const [pqDecap, setPqDecap] = useState("");

  const [asymKeypair, setAsymKeypair] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [recipientPublicKey, setRecipientPublicKey] = useState("");
  const [senderSecretKey, setSenderSecretKey] = useState("");
  const [senderPublicKey, setSenderPublicKey] = useState("");
  const [recipientSecretKey, setRecipientSecretKey] = useState("");
  const [asymCiphertext, setAsymCiphertext] = useState("");
  const [asymPlaintext, setAsymPlaintext] = useState("");
  const [importPayload, setImportPayload] = useState("");

  useEffect(() => {
    const stored = localStorage.getItem("qimem.theme");
    if (stored === "light") {
      setTheme("light");
      document.documentElement.dataset.theme = "light";
    }
    setKeys(loadKeys());
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("qimem.theme", theme);
  }, [theme]);

  const activeStatusColor = useMemo(() => statusColor[status.tone], [status]);

  const handleDeriveKey = async () => {
    try {
      if (!password.trim()) throw new Error("Password is required.");
      const saltBytes = base64ToBytes(salt);
      const keyBytes = await deriveKeyFromPassword(password, saltBytes, kdfMethod);
      const keyB64 = bytesToBase64(keyBytes);
      setDerivedKey(keyB64);
      setStatus({ tone: "success", message: `${kdfMethod} key derived.` });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleEncrypt = async () => {
    try {
      if (!plaintext.trim()) throw new Error("Message cannot be empty.");
      if (!derivedKey) throw new Error("Derive or import a key first.");
      const payload = await encryptAesGcm(base64ToBytes(derivedKey), textToBytes(plaintext));
      const payloadB64 = bytesToBase64(payload);
      setCiphertext(payloadB64);
      setStatus({ tone: "success", message: "Encrypted locally." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleDecrypt = async () => {
    try {
      if (!ciphertext.trim()) throw new Error("Ciphertext required.");
      if (!derivedKey) throw new Error("Derive or import a key first.");
      const payloadBytes = base64ToBytes(ciphertext);
      const plainBytes = await decryptAesGcm(base64ToBytes(derivedKey), payloadBytes);
      setDecryptedText(bytesToText(plainBytes));
      setStatus({ tone: "success", message: "Decrypted locally." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleSelfDestructEncrypt = async () => {
    try {
      const ttl = Number(ttlSeconds);
      if (!ttl || ttl <= 0) throw new Error("TTL must be greater than 0.");
      if (!plaintext.trim()) throw new Error("Message cannot be empty.");
      if (!derivedKey) throw new Error("Derive or import a key first.");
      const expiresAt = Date.now() + ttl * 1000;
      const payload = JSON.stringify({ expiresAt, message: plaintext });
      const cipher = await encryptAesGcm(base64ToBytes(derivedKey), textToBytes(payload));
      setSelfDestructPayload(bytesToBase64(cipher));
      setStatus({ tone: "warning", message: "TTL embedded. Copying duplicates bypass TTL." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleSelfDestructDecrypt = async () => {
    try {
      if (!selfDestructPayload.trim()) throw new Error("Payload required.");
      if (!derivedKey) throw new Error("Derive or import a key first.");
      const plain = await decryptAesGcm(base64ToBytes(derivedKey), base64ToBytes(selfDestructPayload));
      const parsed = JSON.parse(bytesToText(plain)) as { expiresAt: number; message: string };
      const remainingMs = parsed.expiresAt - Date.now();
      if (remainingMs <= 0) {
        setTtlCountdown("Expired");
        throw new Error("This payload has expired.");
      }
      setPlaintext(parsed.message);
      setTtlCountdown(Math.ceil(remainingMs / 1000).toString());
      setStatus({ tone: "success", message: "Payload decrypted. TTL active." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  useEffect(() => {
    if (!ttlCountdown || ttlCountdown === "Expired") return undefined;
    const timer = setInterval(() => {
      setTtlCountdown((prev) => {
        if (!prev || prev === "Expired") return prev;
        const next = Number(prev) - 1;
        return next <= 0 ? "Expired" : next.toString();
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [ttlCountdown]);

  const handleSign = () => {
    try {
      if (!signingKeypair) throw new Error("Generate or import a signing keypair.");
      if (!plaintext.trim()) throw new Error("Message cannot be empty.");
      const signatureBytes = nacl.sign.detached(
        textToBytes(plaintext),
        base64ToBytes(signingKeypair.secretKey),
      );
      setSignature(bytesToBase64(signatureBytes));
      setStatus({ tone: "success", message: "Signature generated." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleVerify = () => {
    try {
      if (!signature.trim()) throw new Error("Signature required.");
      if (!signingKeypair) throw new Error("Provide a public key.");
      const isValid = nacl.sign.detached.verify(
        textToBytes(plaintext),
        base64ToBytes(signature),
        base64ToBytes(signingKeypair.publicKey),
      );
      setVerificationResult({
        tone: isValid ? "success" : "error",
        message: isValid ? "Signature is valid." : "Signature is invalid.",
      });
    } catch (error) {
      setVerificationResult({ tone: "error", message: (error as Error).message });
    }
  };

  const handleGenerateSigningKeypair = () => {
    const keypair = nacl.sign.keyPair();
    const record = {
      publicKey: bytesToBase64(keypair.publicKey),
      secretKey: bytesToBase64(keypair.secretKey),
    };
    setSigningKeypair(record);
    setStatus({ tone: "success", message: "Signing keypair generated." });
  };

  const handleGenerateAsymKeypair = () => {
    const keypair = nacl.box.keyPair();
    const record = {
      publicKey: bytesToBase64(keypair.publicKey),
      secretKey: bytesToBase64(keypair.secretKey),
    };
    setAsymKeypair(record);
    setRecipientPublicKey(record.publicKey);
    setSenderSecretKey(record.secretKey);
    setSenderPublicKey(record.publicKey);
    setRecipientSecretKey(record.secretKey);
    setStatus({ tone: "success", message: "Asymmetric keypair generated." });
  };

  const handleAsymEncrypt = () => {
    try {
      if (!recipientPublicKey.trim() || !senderSecretKey.trim()) {
        throw new Error("Recipient public key and sender secret key are required.");
      }
      const recipientPublic = base64ToBytes(recipientPublicKey);
      const senderSecret = base64ToBytes(senderSecretKey);
      const nonce = randomBytes(nacl.box.nonceLength);
      const cipher = nacl.box(textToBytes(plaintext), nonce, recipientPublic, senderSecret);
      if (!cipher) throw new Error("Encryption failed.");
      const payload = new Uint8Array(nonce.length + cipher.length);
      payload.set(nonce, 0);
      payload.set(cipher, nonce.length);
      setAsymCiphertext(bytesToBase64(payload));
      setStatus({ tone: "success", message: "Asymmetric encryption complete." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleAsymDecrypt = () => {
    try {
      if (!recipientSecretKey.trim() || !senderPublicKey.trim()) {
        throw new Error("Recipient secret key and sender public key are required.");
      }
      if (!asymCiphertext.trim()) throw new Error("Ciphertext required.");
      const payload = base64ToBytes(asymCiphertext);
      const nonce = payload.slice(0, nacl.box.nonceLength);
      const cipher = payload.slice(nacl.box.nonceLength);
      const plain = nacl.box.open(
        cipher,
        nonce,
        base64ToBytes(senderPublicKey),
        base64ToBytes(recipientSecretKey),
      );
      if (!plain) throw new Error("Decryption failed.");
      setAsymPlaintext(bytesToText(plain));
      setStatus({ tone: "success", message: "Asymmetric decryption complete." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleTotp = async () => {
    try {
      const secretBytes = base32Decode(totpSecret);
      const epoch = Math.floor(Date.now() / 1000);
      const counter = Math.floor(epoch / 30);
      const counterBytes = new Uint8Array(8);
      const view = new DataView(counterBytes.buffer);
      view.setBigUint64(0, BigInt(counter));
      const key = await crypto.subtle.importKey(
        "raw",
        secretBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"],
      );
      const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
      const offset = hmac[hmac.length - 1] & 0xf;
      const code =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
      setTotpCode((code % 1_000_000).toString().padStart(6, "0"));
      setStatus({ tone: "success", message: "TOTP generated." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handlePqKeygen = () => {
    const { publicKey, secretKey } = ml_kem1024.keygen();
    setPqKeypair({
      publicKey: bytesToBase64(publicKey),
      secretKey: bytesToBase64(secretKey),
    });
    setStatus({ tone: "success", message: "ML-KEM-1024 keypair generated." });
  };

  const handlePqEncapsulate = () => {
    try {
      if (!pqKeypair) throw new Error("Generate or import a PQ keypair.");
      const { cipherText, sharedSecret } = ml_kem1024.encapsulate(base64ToBytes(pqKeypair.publicKey));
      setPqEncap({
        ciphertext: bytesToBase64(cipherText),
        sharedSecret: bytesToBase64(sharedSecret),
      });
      setStatus({ tone: "success", message: "Shared secret encapsulated." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handlePqDecapsulate = () => {
    try {
      if (!pqKeypair || !pqEncap) throw new Error("Encapsulate first.");
      const shared = ml_kem1024.decapsulate(
        base64ToBytes(pqEncap.ciphertext),
        base64ToBytes(pqKeypair.secretKey),
      );
      setPqDecap(bytesToBase64(shared));
      setStatus({ tone: "success", message: "Shared secret decapsulated." });
    } catch (error) {
      setStatus({ tone: "error", message: (error as Error).message });
    }
  };

  const handleSaveKey = (record: KeyRecord) => {
    const updated = [record, ...keys];
    setKeys(updated);
    saveKeys(updated);
    setStatus({ tone: "success", message: "Key stored locally." });
  };

  const handleDeleteKey = (id: string) => {
    const updated = keys.filter((key) => key.id !== id);
    setKeys(updated);
    saveKeys(updated);
  };

  const handleExportKeys = () => {
    const exportData = JSON.stringify({ exportedAt: new Date().toISOString(), keys }, null, 2);
    const blob = new Blob([exportData], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "qimem-keys.json";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const handleImportKeys = (payload: string) => {
    try {
      const parsed = JSON.parse(payload) as { keys: KeyRecord[] };
      const updated = [...parsed.keys, ...keys];
      setKeys(updated);
      saveKeys(updated);
      setStatus({ tone: "success", message: "Keys imported." });
    } catch (error) {
      setStatus({ tone: "error", message: "Invalid key export JSON." });
    }
  };

  return (
    <main>
      <header>
        <div>
          <h1>QIMEM ቅመም - COMMAND</h1>
          <p>Local-first cryptography control room built for calm, focused operations.</p>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span className="badge">{APP_VERSION}</span>
          <button
            type="button"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            {theme === "dark" ? "Light Mode" : "Dark Mode"}
          </button>
        </div>
      </header>

      <section>
        <h2>What is QIMEM?</h2>
        <p>
          QIMEM is a private cryptography workbench. Every operation you perform in the
          browser stays on your device. The API exists for infrastructure workloads, but
          this console is designed for safe, offline experimentation.
        </p>
        <div className="grid">
          <div className="output">
            <strong>Safe to try:</strong> key generation, encryption, signing, TOTP, PQ sandbox.
          </div>
          <div className="output">
            <strong>Remember:</strong> TTL ≠ destruction if ciphertext is copied or backed up.
          </div>
        </div>
      </section>

      <section className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab}
            type="button"
            className={tab === activeTab ? "tab active" : "tab"}
            onClick={() => setActiveTab(tab)}
          >
            {tab}
          </button>
        ))}
      </section>

      <section>
        <div className="status" style={{ color: activeStatusColor }}>
          {status.message}
        </div>
      </section>

      {activeTab === "Encryption" && (
        <div className="grid">
          <section>
            <h2>Password-based Encryption</h2>
            <label>Password</label>
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" />
            <label>Salt (base64)</label>
            <input value={salt} onChange={(e) => setSalt(e.target.value)} />
            <div className="button-row">
              <button onClick={() => setSalt(bytesToBase64(randomBytes(16)))}>Generate Salt</button>
              <button onClick={() => setPlaintext(DEMO_MESSAGE)}>Load Demo Message</button>
            </div>
            <label>Key Derivation</label>
            <select value={kdfMethod} onChange={(e) => setKdfMethod(e.target.value as "PBKDF2" | "Argon2id")}>
              <option value="Argon2id">Argon2id</option>
              <option value="PBKDF2">PBKDF2 (SHA-256)</option>
            </select>
            <button onClick={handleDeriveKey}>Derive Key</button>
            <div className="output">Derived key: {derivedKey || "-"}</div>
          </section>

          <section>
            <h2>Symmetric Encryption</h2>
            <label>Message</label>
            <textarea rows={4} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
            <div className="button-row">
              <button onClick={handleEncrypt}>Encrypt</button>
              <button onClick={handleDecrypt}>Decrypt</button>
            </div>
            <label>Ciphertext (base64)</label>
            <textarea rows={4} value={ciphertext} onChange={(e) => setCiphertext(e.target.value)} />
            <div className="output">Plaintext: {decryptedText || "-"}</div>
            <div className="button-row">
              <button onClick={() => copyWithWarning("Ciphertext", ciphertext, setStatus)}>Copy</button>
              <button
                onClick={() => {
                  const payload = JSON.stringify(
                    {
                      type: "qimem.symmetric",
                      createdAt: new Date().toISOString(),
                      ciphertext,
                      kdf: kdfMethod,
                      salt,
                    },
                    null,
                    2,
                  );
                  const blob = new Blob([payload], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const anchor = document.createElement("a");
                  anchor.href = url;
                  anchor.download = "qimem-encrypted.json";
                  anchor.click();
                  URL.revokeObjectURL(url);
                }}
              >
                Export JSON
              </button>
            </div>
          </section>

          <section>
            <h2>Asymmetric Encryption</h2>
            <p>Uses Curve25519 via NaCl box for public/private encryption.</p>
            <button onClick={handleGenerateAsymKeypair}>Generate Keypair</button>
            <div className="output">Generated public key: {asymKeypair?.publicKey || "-"}</div>
            <div className="output">Generated secret key: {asymKeypair?.secretKey || "-"}</div>
            <label title="Recipient public key used to encrypt">Recipient Public Key (base64)</label>
            <textarea rows={2} value={recipientPublicKey} onChange={(e) => setRecipientPublicKey(e.target.value)} />
            <label title="Sender secret key used to encrypt">Sender Secret Key (base64)</label>
            <textarea rows={2} value={senderSecretKey} onChange={(e) => setSenderSecretKey(e.target.value)} />
            <div className="button-row">
              <button onClick={handleAsymEncrypt}>Encrypt</button>
            </div>
            <label>Asymmetric Ciphertext (base64)</label>
            <textarea rows={3} value={asymCiphertext} onChange={(e) => setAsymCiphertext(e.target.value)} />
            <label title="Sender public key used to decrypt">Sender Public Key (base64)</label>
            <textarea rows={2} value={senderPublicKey} onChange={(e) => setSenderPublicKey(e.target.value)} />
            <label title="Recipient secret key used to decrypt">Recipient Secret Key (base64)</label>
            <textarea rows={2} value={recipientSecretKey} onChange={(e) => setRecipientSecretKey(e.target.value)} />
            <div className="button-row">
              <button onClick={handleAsymDecrypt}>Decrypt</button>
            </div>
            <div className="output">Decrypted: {asymPlaintext || "-"}</div>
          </section>
        </div>
      )}

      {activeTab === "Self-Destruct" && (
        <div className="grid">
          <section>
            <h2>Self-Destruct Payload</h2>
            <p>TTL is embedded in the payload. If the ciphertext is copied, TTL still expires here only.</p>
            <label>TTL (seconds)</label>
            <input value={ttlSeconds} onChange={(e) => setTtlSeconds(e.target.value)} />
            <button onClick={handleSelfDestructEncrypt}>Encrypt with TTL</button>
            <label>Payload (base64)</label>
            <textarea rows={4} value={selfDestructPayload} onChange={(e) => setSelfDestructPayload(e.target.value)} />
            <button onClick={handleSelfDestructDecrypt}>Decrypt & Start Countdown</button>
            <div className="output">TTL Remaining: {ttlCountdown ?? "-"}</div>
          </section>
        </div>
      )}

      {activeTab === "Signing" && (
        <div className="grid">
          <section>
            <h2>Ed25519 Signing</h2>
            <button onClick={handleGenerateSigningKeypair}>Generate Keypair</button>
            <div className="output">Public key: {signingKeypair?.publicKey || "-"}</div>
            <div className="output">Secret key: {signingKeypair?.secretKey || "-"}</div>
            <button onClick={handleSign}>Sign Message</button>
            <label>Signature (base64)</label>
            <textarea rows={3} value={signature} onChange={(e) => setSignature(e.target.value)} />
            <div className="button-row">
              <button onClick={handleVerify}>Verify Signature</button>
              <button onClick={() => copyWithWarning("Signature", signature, setStatus)}>Copy</button>
            </div>
            <div className="output" style={{ color: statusColor[verificationResult.tone] }}>
              {verificationResult.message || "Verification status will appear here."}
            </div>
          </section>
        </div>
      )}

      {activeTab === "TOTP" && (
        <div className="grid">
          <section>
            <h2>TOTP Generator</h2>
            <p>Use a Base32 seed to generate 6-digit codes.</p>
            <label>Seed (Base32)</label>
            <input value={totpSecret} onChange={(e) => setTotpSecret(e.target.value)} />
            <button onClick={handleTotp}>Generate Code</button>
            <div className="output">Code: {totpCode || "-"}</div>
            <button onClick={() => copyWithWarning("TOTP code", totpCode, setStatus)}>Copy</button>
          </section>
        </div>
      )}

      {activeTab === "Post-Quantum" && (
        <div className="grid">
          <section>
            <h2>ML-KEM-1024 Sandbox</h2>
            <p>Post-quantum encapsulation for shared secret bootstrapping.</p>
            <button onClick={handlePqKeygen}>Generate Keypair</button>
            <div className="output">Public key: {pqKeypair?.publicKey || "-"}</div>
            <div className="output">Secret key: {pqKeypair?.secretKey || "-"}</div>
            <button onClick={handlePqEncapsulate}>Encapsulate</button>
            <div className="output">Ciphertext: {pqEncap?.ciphertext || "-"}</div>
            <div className="output">Shared secret: {pqEncap?.sharedSecret || "-"}</div>
            <button onClick={handlePqDecapsulate}>Decapsulate</button>
            <div className="output">Decapsulated secret: {pqDecap || "-"}</div>
          </section>
        </div>
      )}

      {activeTab === "Keys" && (
        <div className="grid">
          <section>
            <h2>Key Management</h2>
            <p>Keys are stored in localStorage. Clear your browser data to remove them.</p>
            <div className="button-row">
              <button
                onClick={() =>
                  handleSaveKey({
                    id: crypto.randomUUID(),
                    name: `Symmetric-${new Date().toISOString()}`,
                    type: "symmetric",
                    createdAt: new Date().toISOString(),
                    material: { key: bytesToBase64(randomBytes(32)) },
                  })
                }
              >
                Generate Symmetric Key
              </button>
              <button
                onClick={() =>
                  handleSaveKey({
                    id: crypto.randomUUID(),
                    name: `Signing-${new Date().toISOString()}`,
                    type: "signing",
                    createdAt: new Date().toISOString(),
                    material: signingKeypair || { publicKey: "", secretKey: "" },
                  })
                }
              >
                Store Signing Keypair
              </button>
            </div>
            <button onClick={handleExportKeys}>Export JSON</button>
            <label>Import JSON</label>
            <textarea
              rows={3}
              placeholder="Paste export JSON"
              value={importPayload}
              onChange={(e) => setImportPayload(e.target.value)}
            />
            <button
              onClick={() => {
                if (importPayload.trim()) {
                  handleImportKeys(importPayload);
                  setImportPayload("");
                }
              }}
            >
              Import Keys
            </button>
          </section>

          <section>
            <h2>Stored Keys</h2>
            {keys.length === 0 && <p>No keys stored yet.</p>}
            {keys.map((key) => (
              <div key={key.id} className="output">
                <strong>{key.name}</strong> — {key.type}
                <div>Created: {key.createdAt}</div>
                <div className="button-row">
                  <button onClick={() => copyWithWarning("Key JSON", JSON.stringify(key), setStatus)}>Copy JSON</button>
                  <button onClick={() => handleDeleteKey(key.id)}>Delete</button>
                </div>
              </div>
            ))}
          </section>
        </div>
      )}

      <section>
        <h2>Beta Feedback</h2>
        <p>
          Report issues or request features:{" "}
          <a href="mailto:ops@qimem.local">ops@qimem.local</a> ·{" "}
          <a href="https://github.com/qimem/qimem/issues" target="_blank" rel="noreferrer">
            GitHub Issues
          </a>
        </p>
        <div className="output">
          <strong>Changelog</strong>
          <ul>
            {CHANGELOG.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
