# QIMEM + QAuth Unified API

## Versioned base path
- `GET /health`
- `GET /ready`
- `GET /v1/security/health`

## Security (QIMEM)
- `POST /v1/security/keys`
- `POST /v1/security/encrypt`
- `POST /v1/security/decrypt`
- `POST /v1/security/rotate`

## Auth (QAuth)
- `POST /v1/auth/realms`
- `POST /v1/auth/roles`
- `POST /v1/auth/clients`
- `POST /v1/auth/users`
- `POST /v1/auth/token`
- `POST /v1/auth/token/refresh`
- `POST /v1/auth/token/revoke`
- `POST /v1/auth/token/introspect`
- `POST /v1/auth/keys/rotate`

## Plugin manifests
- `GET /v1/plugins/manifests`
- `POST /v1/plugins/manifests`

## Canonical error shape
```json
{
  "error": "human readable error"
}
```

## Login Example
```bash
curl -X POST http://localhost:8080/v1/auth/token \
  -H 'content-type: application/json' \
  -d '{
    "client_id":"...",
    "client_secret":"...",
    "realm_id":"acme",
    "username":"alice",
    "password":"secret"
  }'
```
