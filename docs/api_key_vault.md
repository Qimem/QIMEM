# Secure API Key Vault

## Design
- API keys are encrypted client-side with DEK.
- DEKs are wrapped by tenant master keys.
- Vault stores only encrypted key material and metadata.

## Access Model
- Short-lived access tokens for retrieval.
- Strict tenant binding for read/write operations.
- All access logged with audit chain.

## Use Cases
- Protect OpenAI, Anthropic, Stripe, or internal service keys.
- Allow secure runtime retrieval for gateway or tenant services.
