import { Qimem } from "@qimem/sdk";

const API_BASE = process.env.QIMEM_API_BASE_URL ?? "http://localhost:8080";
const apiKey = process.env.QIMEM_API_KEY;

if (!apiKey) {
  console.error("Missing QIMEM_API_KEY");
  process.exit(1);
}

async function createTenant() {
  const response = await fetch(`${API_BASE}/v1/kms/tenants`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "X-Tenant-ID": crypto.randomUUID(),
    },
    body: JSON.stringify({ name: "sdk-basic" }),
  });
  if (!response.ok) {
    throw new Error(`Create tenant failed (${response.status})`);
  }
  return response.json();
}

async function rotateMasterKey(tenantId) {
  const response = await fetch(`${API_BASE}/v1/kms/rotate-master-key`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "X-Tenant-ID": tenantId,
    },
  });
  if (!response.ok) {
    throw new Error(`Rotate master key failed (${response.status})`);
  }
  return response.json();
}

async function main() {
  const tenant = await createTenant();
  const client = new Qimem({
    apiKey,
    tenantId: tenant.tenant_id,
    baseUrl: API_BASE,
  });

  const encrypted = await client.encrypt("hello from sdk");
  const decrypted = await client.decrypt(encrypted);
  console.log("Decrypted:", decrypted);

  await rotateMasterKey(tenant.tenant_id);
  const decryptedAfterRotation = await client.decrypt(encrypted);
  console.log("Decrypted after rotation:", decryptedAfterRotation);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
