# QIMEM API

## Endpoints
- `GET /health` -> `{ "status": "ok" }`
- `POST /keys` -> `{ "key_id": "..." }`
- `POST /encrypt` -> expects `{ "key_id": "...", "input": "..." }`, returns `{ "envelope": "..." }`
- `POST /decrypt` -> expects `{ "input": "..." }`, returns `{ "plaintext": "..." }`
- `POST /rotate` -> rotate key

## Request/response examples

### Create key
```bash
curl -fsS -X POST http://localhost:8080/keys \
  -H 'content-type: application/json' \
  -d '{}'

# => {"key_id":"<uuid>"}
```

### Encrypt
Canonical request payload uses `input`:

```json
{
  "key_id": "<uuid>",
  "input": "hello"
}
```

```bash
curl -fsS -X POST http://localhost:8080/encrypt \
  -H 'content-type: application/json' \
  -d '{"key_id":"<uuid>","input":"hello"}'

# => {"envelope":"<base64-envelope>"}
```

### Decrypt
```bash
curl -fsS -X POST http://localhost:8080/decrypt \
  -H 'content-type: application/json' \
  -d '{"input":"<base64-envelope>"}'

# => {"plaintext":"hello"}
```

QIMEM intentionally has no authentication features.
