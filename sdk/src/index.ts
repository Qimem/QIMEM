import { encode, decode } from "@stablelib/base64";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { randomBytes } from "@stablelib/random";

export type InitConfig = {
  apiKey: string;
  tenantId: string;
  baseUrl?: string;
};

export type EncryptedBlob = {
  ciphertext: string;
  wrappedDek: string;
  keyVersion: number;
  nonce: string;
  algorithm: string;
};

export type SecurePromptOptions = {
  provider: "mock" | "openai-compatible" | "custom";
  providerConfig?: {
    endpoint?: string;
    headers?: Record<string, string>;
    model?: string;
  };
};

export class Qimem {
  private apiKey: string;
  private tenantId: string;
  private baseUrl: string;

  constructor({ apiKey, tenantId, baseUrl }: InitConfig) {
    this.apiKey = apiKey;
    this.tenantId = tenantId;
    this.baseUrl = baseUrl ?? "http://localhost:8080";
  }

  async encrypt(data: string): Promise<EncryptedBlob> {
    const dek = randomBytes(32);
    const nonce = randomBytes(12);
    const cipher = new ChaCha20Poly1305(dek);
    const ciphertext = cipher.seal(nonce, new TextEncoder().encode(data));
    const wrappedDekResponse = await this.wrapDek(dek);
    dek.fill(0);
    return {
      ciphertext: encode(ciphertext),
      wrappedDek: wrappedDekResponse.wrapped_dek,
      keyVersion: wrappedDekResponse.key_version,
      nonce: encode(nonce),
      algorithm: "chacha20poly1305",
    };
  }

  async decrypt(blob: EncryptedBlob): Promise<string> {
    const dek = await this.unwrapDek(blob.wrappedDek, blob.keyVersion);
    const cipher = new ChaCha20Poly1305(dek);
    const plaintext = cipher.open(decode(blob.nonce), decode(blob.ciphertext));
    dek.fill(0);
    if (!plaintext) {
      throw new Error("Failed to decrypt payload");
    }
    const text = new TextDecoder().decode(plaintext);
    plaintext.fill(0);
    return text;
  }

  async sign(message: string) {
    return this.post("/v1/sign", { message });
  }

  async verify(signatureB64: string, message: string, publicKeyB64: string) {
    const response = await this.post("/v1/verify", {
      signature_b64: signatureB64,
      message,
      public_key_b64: publicKeyB64,
    });
    return response.valid as boolean;
  }

  async pqSession(serverPublicKeyB64: string) {
    return this.post("/v1/kms/pq/session", { client_public_key_b64: serverPublicKeyB64 });
  }

  async wrapDek(dek: Uint8Array): Promise<{ wrapped_dek: string; key_version: number }> {
    return this.post("/v1/kms/wrap-dek", { dek_b64: encode(dek) });
  }

  async unwrapDek(wrappedDek: string, keyVersion: number): Promise<Uint8Array> {
    const data = await this.post("/v1/kms/unwrap-dek", {
      wrapped_dek_b64: wrappedDek,
      key_version: keyVersion,
    });
    return decode(data.dek_b64);
  }

  async gatewayProxy(payload: EncryptedBlob, options: SecurePromptOptions) {
    return this.post("/v1/gateway/proxy", {
      provider: options.provider,
      encrypted_payload: payload.ciphertext,
      wrapped_dek: payload.wrappedDek,
      key_version: payload.keyVersion,
      provider_config: options.providerConfig ?? {},
      nonce: payload.nonce,
      algorithm: payload.algorithm,
    });
  }

  private baseHeaders() {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
      "X-Tenant-ID": this.tenantId,
    };
  }

  private async post(path: string, body: unknown) {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: this.baseHeaders(),
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`${path} failed: ${response.status}`);
    }
    return response.json();
  }
}

export function init(config: InitConfig) {
  return new Qimem(config);
}

export async function encrypt(client: Qimem, data: string) {
  return client.encrypt(data);
}

export async function decrypt(client: Qimem, blob: EncryptedBlob) {
  return client.decrypt(blob);
}

export async function sign(client: Qimem, message: string) {
  return client.sign(message);
}

export async function verify(client: Qimem, signatureB64: string, message: string, publicKeyB64: string) {
  return client.verify(signatureB64, message, publicKeyB64);
}

export async function pqSession(client: Qimem, serverPublicKeyB64: string) {
  return client.pqSession(serverPublicKeyB64);
}

export async function wrapDek(client: Qimem, dek: Uint8Array) {
  return client.wrapDek(dek);
}

export async function unwrapDek(client: Qimem, wrappedDek: string, keyVersion: number) {
  return client.unwrapDek(wrappedDek, keyVersion);
}

export async function gatewayProxy(client: Qimem, payload: EncryptedBlob, options: SecurePromptOptions) {
  return client.gatewayProxy(payload, options);
}
