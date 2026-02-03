# QIMEM Web Console

The web console is a monochrome, minimal command interface designed for secure operations.

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

Paste a Better Auth JWT into the control panel to authorize requests. Tokens are
stored locally in the browser for the session.

## Vercel Deployment

1. Create a new Vercel project and set the **Root Directory** to `web/`.
2. Configure environment variables:
   - `NEXT_PUBLIC_API_BASE_URL` pointing to the QIMEM API (HTTPS).
3. Deploy. The project includes `web/vercel.json` with default build settings.
