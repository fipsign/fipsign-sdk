# fipsign-sdk

[![npm](https://img.shields.io/npm/v/fipsign-sdk)](https://www.npmjs.com/package/fipsign-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-blue)](https://csrc.nist.gov/pubs/fips/204/final)

Post-quantum signing SDK for Node.js and the browser. Signs and verifies any payload using **ML-DSA-65** (NIST FIPS 204) — resistant to Shor's algorithm, standardized by NIST in August 2024.

**Not just for auth.** Sign users, orders, documents, devices, AI agents, events — any entity that needs a tamper-proof, quantum-resistant signature.

📖 **[Full documentation, API reference, and guides →](https://fipsign.dev/guide)**

---

## Install

```bash
npm install fipsign-sdk
```

---

## Quick start

1. Create a free account at [app.fipsign.dev](https://app.fipsign.dev).
2. In the dashboard, create a project, then create an API key inside it. Save the key — it won't be shown again.
3. Use it:

```typescript
import { PQAuth } from 'fipsign-sdk'

const fipsign = new PQAuth('pqa_your_api_key')

const { token } = await fipsign.sign({ sub: 'user_123', role: 'admin' })

const { valid, payload } = await fipsign.verify(token)
if (!valid) throw new Error('invalid token')

console.log(payload.sub) // 'user_123'
```

That's signing and verifying. The SDK also covers offline (in-memory) verification, revocation, webhooks, and a full Certificate Authority module (PQCert + X.509) for issuing post-quantum certificates to devices and services — all in the [developer guide](https://fipsign.dev/guide).

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens rely on ECDSA or RSA — both breakable by Shor's algorithm on a sufficiently powerful quantum computer. ML-DSA-65 is based on lattice problems (Module-LWE / Module-SIS) with no known quantum speedup. Standardized by NIST in August 2024 as FIPS 204.

---

## Links

- 📖 [Developer guide — full API reference, error codes, webhooks, CA/X.509](https://fipsign.dev/guide)
- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)