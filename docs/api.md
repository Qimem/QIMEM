# QIMEM API

## Endpoints
- `GET /health` -> `{ "status": "ok" }`
- `POST /keys` -> create key
- `POST /encrypt` -> encrypt payload by key id
- `POST /decrypt` -> decrypt base64 envelope
- `POST /rotate` -> rotate key

## Request/response examples

### Create key
```bash
curl -fsS -X POST http://localhost:8080/keys \
  -H 'content-type: application/json' \
  -d '{}'
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
```

### Decrypt
```bash
curl -fsS -X POST http://localhost:8080/decrypt \
  -H 'content-type: application/json' \
  -d '{"input":"<base64-envelope>"}'
```

QIMEM intentionally has no authentication features.
