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
