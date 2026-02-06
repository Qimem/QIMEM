# QIMEM Web Console

The web console is a **Security Control Plane** for tenant and key management, policy configuration, audit inspection, and vault administration.

## Local Setup

```
cd web
cp .env.example .env.local
npm install
npm run dev
```

## Environment

- `NEXT_PUBLIC_API_BASE_URL` — Base URL of the QIMEM API.

## Access

- The console requires authenticated access with tenant-scoped JWTs.
- No cryptographic demo operations are exposed in the UI.

## Vercel Deployment

1. Create a new Vercel project and set the **Root Directory** to `web/`.
2. Configure environment variables:
   - `NEXT_PUBLIC_API_BASE_URL` pointing to the QIMEM API (HTTPS).
3. Deploy. The project includes `web/vercel.json` with default build settings.
