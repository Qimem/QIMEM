# Post-Quantum Strategy

## Hybrid Key Exchange
- Combine X25519 and Kyber1024.
- Derive session keys with HKDF over concatenated shared secrets.

## Crypto Agility
- Algorithms are policy-configured and versioned.
- Payload metadata includes algorithm identifiers.
- SDK negotiates algorithms during session initiation.

## Migration Plan
- New algorithm policies apply to new sessions and key wraps.
- Existing encrypted data remains readable by including algorithm metadata.
- Background rewraps allow gradual migration without downtime.
