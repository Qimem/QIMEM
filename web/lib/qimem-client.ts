export type ClientConfig = {
  baseUrl: string;
  jwt: string;
  tenantId: string;
};

export type ApiError = {
  status: number;
  message: string;
  details?: unknown;
};

export type KmsEncryptResponse = {
  ciphertext_b64: string;
  wrapped_dek_b64: string;
  key_version: number;
  nonce_b64: string;
  algorithm: string;
};

export type KmsDecryptResponse = {
  plaintext_b64: string;
};

export type KmsSignResponse = {
  signature_b64: string;
  public_key_b64: string;
};

export type KmsVerifyResponse = {
  valid: boolean;
};

export type PqKeypairResponse = {
  algorithm: string;
  version: number;
  public_key_b64: string;
};

export type PqSessionResponse = {
  algorithm: string;
  algorithm_id: string;
  version: number;
  timestamp: number;
  server_x25519_public_key_b64: string;
  kyber_ciphertext_b64: string;
  session_key_b64: string;
};

export type PqX25519Response = {
  public_key_b64: string;
};

export type DeriveKeyResponse = {
  key_b64: string;
  salt_b64: string;
};

export type LegacyEncryptResponse = {
  ciphertext_b64: string;
  expires_at?: number | null;
};

export type LegacyDecryptResponse = {
  plaintext_b64: string;
  expires_at?: number | null;
};

export type AuditLogEntry = {
  id: string;
  tenant_id: string;
  event_type: string;
  event_hash_b64: string;
  prev_hash_b64?: string | null;
  metadata: unknown;
  created_at: number;
};

type RequestOverrides = {
  jwt?: string;
  tenantId?: string;
};

async function parseJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function request<T>(
  config: ClientConfig,
  path: string,
  options: RequestInit,
  overrides: RequestOverrides = {},
): Promise<T> {
  const jwt = overrides.jwt ?? config.jwt;
  const tenantId = overrides.tenantId ?? config.tenantId;
  if (!jwt || !tenantId) {
    throw { status: 401, message: "Missing JWT or tenant ID" } satisfies ApiError;
  }

  const response = await fetch(`${config.baseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
      "X-Tenant-ID": tenantId,
      ...(options.headers ?? {}),
    },
  });

  const payload = await parseJson(response);
  if (!response.ok) {
    const message =
      typeof payload === "object" && payload && "error" in payload
        ? String((payload as { error?: string }).error)
        : response.statusText;
    throw { status: response.status, message, details: payload } satisfies ApiError;
  }
  return payload as T;
}

export function createQimemClient(config: ClientConfig) {
  return {
    kmsEncrypt: (plaintext_b64: string) =>
      request<KmsEncryptResponse>(config, "/v1/kms/encrypt", {
        method: "POST",
        body: JSON.stringify({ plaintext_b64 }),
      }),
    kmsDecrypt: (
      payload: {
        ciphertext_b64: string;
        wrapped_dek_b64: string;
        key_version: number;
        nonce_b64: string;
        algorithm: string;
      },
      overrides?: RequestOverrides,
    ) =>
      request<KmsDecryptResponse>(
        config,
        "/v1/kms/decrypt",
        {
          method: "POST",
          body: JSON.stringify(payload),
        },
        overrides,
      ),
    kmsSign: (message_b64: string) =>
      request<KmsSignResponse>(config, "/v1/kms/sign", {
        method: "POST",
        body: JSON.stringify({ message_b64 }),
      }),
    kmsVerify: (payload: { message_b64: string; public_key_b64: string; signature_b64: string }) =>
      request<KmsVerifyResponse>(config, "/v1/kms/verify", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    pqKeypair: (algorithm?: string) =>
      request<PqKeypairResponse>(config, "/v1/kms/pq/keypair", {
        method: "POST",
        body: JSON.stringify({ algorithm }),
      }),
    pqX25519: () =>
      request<PqX25519Response>(config, "/v1/kms/pq/x25519", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    pqSession: (payload: {
      algorithm?: string;
      client_x25519_public_key_b64: string;
      client_kyber_public_key_b64: string;
    }) =>
      request<PqSessionResponse>(config, "/v1/kms/pq/session", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    deriveKey: (password: string) =>
      request<DeriveKeyResponse>(config, "/v0/derive-key", {
        method: "POST",
        body: JSON.stringify({ password }),
      }),
    legacyEncrypt: (payload: { plaintext_b64: string; key_b64: string; expires_in_seconds?: number }) =>
      request<LegacyEncryptResponse>(config, "/v0/encrypt", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    legacyDecrypt: (payload: { ciphertext_b64: string; key_b64: string }) =>
      request<LegacyDecryptResponse>(config, "/v0/decrypt", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    auditLogs: (limit = 25) =>
      request<AuditLogEntry[]>(config, `/v1/kms/audit?limit=${limit}`, {
        method: "GET",
      }),
    rawRequest: <T>(path: string, options: RequestInit, overrides?: RequestOverrides) =>
      request<T>(config, path, options, overrides),
  };
}
