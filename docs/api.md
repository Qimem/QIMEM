# QIMEM API

## Endpoints
- `GET /health` -> `{ "status": "ok" }`
- `POST /keys` -> create key
- `POST /encrypt` -> encrypt payload by key id
- `POST /decrypt` -> decrypt base64 envelope
- `POST /rotate` -> rotate key

QIMEM intentionally has no authentication features.
