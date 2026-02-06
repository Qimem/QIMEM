# SDK Basic Example

This example installs the SDK from the package manager and performs a full flow:

1. Create a tenant.
2. Encrypt a payload.
3. Decrypt the payload.
4. Rotate the tenant master key and decrypt again.

## Install

```bash
npm install
```

## Run

```bash
export QIMEM_API_BASE_URL=http://localhost:8080
export QIMEM_API_KEY=<jwt>

npm start
```

The example uses the mock provider via the gateway and prints decrypted payloads
to stdout for verification only.
