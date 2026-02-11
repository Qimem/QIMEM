# QIMEM API (Private)

## Authentication

By default the API can run without authentication for local or beta testing by
setting `QIMEM_AUTH_DISABLED=true`. When auth is enabled, all calls require a JWT:

```
Authorization: Bearer <token>
```

The API validates the JWT signature using `QIMEM_AUTH_JWT_SECRET`. Optionally set
`QIMEM_AUTH_ISSUER` and `QIMEM_AUTH_AUDIENCE` to enforce issuer/audience.

## Policy Controls

- **Geofencing**: Set `QIMEM_ALLOWED_COUNTRIES=US,GB` to restrict access.
- **MFA**: Set `QIMEM_REQUIRE_MFA=true` and `QIMEM_MFA_TOTP_SECRET=<base64>`.

## Endpoints

### POST /v1/derive-key

```json
{
  "password": "...",
  "salt_phrase": "optional",
  "device_fingerprint": "optional"
}
```

### POST /v1/encrypt

```json
{
  "plaintext_b64": "...",
  "key_b64": "...",
  "expires_in_seconds": 3600
}
```

### POST /v1/decrypt

```json
{
  "ciphertext_b64": "...",
  "key_b64": "..."
}
```

### POST /v1/sign

```json
{
  "message_b64": "...",
  "secret_key_b64": "..."
}
```

### POST /v1/verify

```json
{
  "message_b64": "...",
  "public_key_b64": "...",
  "signature_b64": "..."
}
```

### POST /v1/totp/secret

Returns a base64 TOTP secret.

### POST /v1/totp/code

```json
{
  "secret_b64": "..."
}
```

### POST /v1/totp/verify

```json
{
  "secret_b64": "...",
  "code": "123456"
}
```

### POST /v1/pq/keypair

Returns Kyber1024 public/secret keys.

### POST /v1/pq/encapsulate

```json
{ "public_key_b64": "..." }
```

### POST /v1/pq/decapsulate

```json
{ "secret_key_b64": "...", "ciphertext_b64": "..." }
```
