import { encode, decode } from "@stablelib/base64";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { randomBytes } from "@stablelib/random";

type InitConfig = {
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
  provider: "mock" | "custom";
  providerConfig?: {
    endpoint?: string;
    headers?: Record<string, string>;
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
    if (!plaintext) {
      throw new Error("Failed to decrypt payload");
    }
    const text = new TextDecoder().decode(plaintext);
    plaintext.fill(0);
    return text;
  }

  async wrapApiKey(apiKey: string): Promise<EncryptedBlob> {
    return this.encrypt(apiKey);
  }

  async securePrompt(prompt: string, options: SecurePromptOptions) {
    const encrypted = await this.encrypt(prompt);
    const response = await fetch(`${this.baseUrl}/v1/gateway/proxy`, {
      method: "POST",
      headers: this.baseHeaders(),
      body: JSON.stringify({
        provider: options.provider,
        encrypted_payload: encrypted.ciphertext,
        wrapped_dek: encrypted.wrappedDek,
        key_version: encrypted.keyVersion,
        provider_config: options.providerConfig ?? {},
        nonce: encrypted.nonce,
        algorithm: encrypted.algorithm,
      }),
    });
    if (!response.ok) {
      throw new Error(`Gateway error: ${response.status}`);
    }
    return response.json();
  }

  private baseHeaders() {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
      "X-Tenant-ID": this.tenantId,
    };
  }

  private async wrapDek(dek: Uint8Array): Promise<{ wrapped_dek: string; key_version: number }> {
    const response = await fetch(`${this.baseUrl}/v1/kms/wrap-dek`, {
      method: "POST",
      headers: this.baseHeaders(),
      body: JSON.stringify({
        dek_b64: encode(dek),
      }),
    });
    if (!response.ok) {
      throw new Error(`Failed to wrap DEK: ${response.status}`);
    }
    return response.json();
  }

  private async unwrapDek(wrappedDek: string, keyVersion: number): Promise<Uint8Array> {
    const response = await fetch(`${this.baseUrl}/v1/kms/unwrap-dek`, {
      method: "POST",
      headers: this.baseHeaders(),
      body: JSON.stringify({
        wrapped_dek_b64: wrappedDek,
        key_version: keyVersion,
      }),
    });
    if (!response.ok) {
      throw new Error(`Failed to unwrap DEK: ${response.status}`);
    }
    const data = await response.json();
    return decode(data.dek_b64);
  }
}

export function init(config: InitConfig) {
  return new Qimem(config);
}
