# Audit Log Schema

## Event Record
```json
{
  "event_id": "evt_123",
  "tenant_id": "t_123",
  "timestamp": "2024-01-01T00:00:00Z",
  "actor": {
    "type": "service|user",
    "id": "user_123",
    "ip": "203.0.113.4"
  },
  "action": "wrap|unwrap|rotate|gateway_decrypt|vault_read|vault_write",
  "resource": {
    "type": "key|gateway|vault",
    "id": "res_456"
  },
  "result": "success|deny",
  "reason": "policy|auth|rate_limit|expired_token",
  "crypto": {
    "key_version": 1,
    "algorithms": {
      "kem": "x25519+kyber1024",
      "aead": "chacha20poly1305"
    }
  },
  "integrity": {
    "prev_hash": "...",
    "hash": "...",
    "chain_root": "..."
  }
}
```

## Integrity Model
- Each event includes `prev_hash` linking to the previous event.
- A periodic `chain_root` is anchored in a write-once store.
- Verification tool checks continuity and hash validity.
