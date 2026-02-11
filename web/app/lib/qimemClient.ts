export type Credentials = {
  jwt: string;
  tenantId: string;
};

export type ApiError = {
  status: number;
  message: string;
  details?: unknown;
};

export type EncryptResponse = {
  ciphertext_b64: string;
  wrapped_dek_b64: string;
  key_version: number;
  nonce_b64: string;
  algorithm: string;
};

export type SignResponse = {
  signature_b64: string;
  public_key_b64: string;
};

export type VerifyResponse = {
  valid: boolean;
};

export type PQKeypair = {
  algorithm: string;
  version: number;
  public_key_b64: string;
};

export type PQSessionResponse = {
  algorithm: string;
  algorithm_id: string;
  version: number;
  timestamp: number;
  server_x25519_public_key_b64: string;
  kyber_ciphertext_b64: string;
  session_key_b64: string;
};

export type SelfDestructResponse = {
  ciphertext_b64: string;
  expires_at?: number | null;
};

export type AuditEntry = {
  id: string;
  tenant_id: string;
  event_type: string;
  event_hash_b64: string;
  prev_hash_b64?: string | null;
  metadata: unknown;
  created_at: number;
};

type DecryptResponse = { plaintext_b64: string };

type ClientConfig = {
  baseUrl: string;
  getCredentials: () => Credentials;
};

const toBase64 = (value: string) => btoa(new TextEncoder().encode(value).reduce((acc, byte) => acc + String.fromCharCode(byte), ""));
const fromBase64 = (value: string) => {
  const decoded = atob(value);
  const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

async function parseResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function request<T>(config: ClientConfig, path: string, init: RequestInit): Promise<T> {
  const { jwt, tenantId } = config.getCredentials();
  if (!jwt || !tenantId) {
    throw { status: 401, message: "Set JWT and Tenant ID before making API calls." } satisfies ApiError;
  }

  const response = await fetch(`${config.baseUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
      "X-Tenant-ID": tenantId,
      ...(init.headers ?? {}),
    },
  });

  const payload = await parseResponse(response);
  if (!response.ok) {
    const message =
      typeof payload === "object" && payload && "error" in payload
        ? String((payload as { error?: string }).error)
        : response.statusText || "Request failed";
    throw { status: response.status, message, details: payload } satisfies ApiError;
  }
  return payload as T;
}

export function createQimemClient(config: ClientConfig) {
  return {
    encrypt: (payload: string) =>
      request<EncryptResponse>(config, "/v1/kms/encrypt", {
        method: "POST",
        body: JSON.stringify({ plaintext_b64: toBase64(payload) }),
      }),

    decrypt: async (blob: EncryptResponse) => {
      const response = await request<DecryptResponse>(config, "/v1/kms/decrypt", {
        method: "POST",
        body: JSON.stringify(blob),
      });
      return fromBase64(response.plaintext_b64);
    },

    sign: (message: string) =>
      request<SignResponse>(config, "/v1/kms/sign", {
        method: "POST",
        body: JSON.stringify({ message_b64: toBase64(message) }),
      }),

    verify: async (signature: string, message: string, publicKey: string) => {
      const response = await request<VerifyResponse>(config, "/v1/kms/verify", {
        method: "POST",
        body: JSON.stringify({ signature_b64: signature, message_b64: toBase64(message), public_key_b64: publicKey }),
      });
      return response.valid;
    },

    pqKeypair: () =>
      request<PQKeypair>(config, "/v1/kms/pq/keypair", { method: "POST", body: JSON.stringify({}) }),

    pqSession: (publicKey: string) =>
      request<PQSessionResponse>(config, "/v1/kms/pq/session", {
        method: "POST",
        body: JSON.stringify({ client_x25519_public_key_b64: publicKey, client_kyber_public_key_b64: publicKey }),
      }),

    selfDestruct: (payload: string, ttl: number) =>
      request<SelfDestructResponse>(config, "/v0/encrypt", {
        method: "POST",
        body: JSON.stringify({ plaintext_b64: toBase64(payload), key_b64: toBase64("demo-static-key"), expires_in_seconds: ttl }),
      }),

    selfDestructDecrypt: (ciphertext_b64: string) =>
      request<DecryptResponse>(config, "/v0/decrypt", {
        method: "POST",
        body: JSON.stringify({ ciphertext_b64, key_b64: toBase64("demo-static-key") }),
      }),

    getAuditChain: () => request<AuditEntry[]>(config, "/v1/kms/audit?limit=25", { method: "GET" }),
  };
}
