# QIMEM MVP

QIMEM ships multiple binaries and a lightweight dashboard client.

## Binaries

- `qimem` — interactive CLI crypto demo.
- `qimem-api` — minimal API (`/health`, `/encrypt`, `/decrypt`) with optional auth/db config.
- `qimem-gateway` — gateway with `/health` and proxy route; runs even when KMS/db are not configured.
- `qimem-root-rotation` — rotation worker; disabled by default.

## Quick start (under 2 minutes)

```bash
cp .env.example .env
cargo build
cargo run --bin qimem-api
```

In a second terminal:

```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/encrypt \
  -H 'content-type: application/json' \
  -d '{"data":"hello","key":"demo-key"}'
```

## Run the CLI

```bash
cargo run --bin qimem
```

## Run gateway

```bash
cargo run --bin qimem-gateway
```

## Run root rotation

By default it logs a skip unless explicitly enabled:

```bash
QIMEM_ROOT_ROTATION_ENABLED=true cargo run --bin qimem-root-rotation -- --dry-run
```

## Dashboard client

A Tailwind + React dashboard lives in `client/`.

```bash
cd client
npm install
npm run dev
```

The client proxies API calls to `http://127.0.0.1:8080`.

## Docker compose (local MVP)

```bash
docker compose up -d postgres
cargo run --bin qimem-api
```

You can optionally wire API/gateway/client as additional compose services as your local workflow evolves.
