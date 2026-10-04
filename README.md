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

## When verify() says no

`verify()` never throws. When `valid` is `false`, `failure` says why:

| `failure` | Meaning | What to do |
|---|---|---|
| `'rejected'` | The token is not acceptable (bad signature, expired, revoked, ...) | Answer 401 |
| `'rate_limited'` | Too many requests in the current minute. The token was not checked | Wait `retryAfter` seconds and try again |
| `'quota_exhausted'` | Free tokens and packs used up. The token was not checked | Buy a pack from the dashboard |
| `'unavailable'` | FIPSign could not answer (timeout, network, server error, invalid API key). The token was not checked | Try again; answer 503 |

```typescript
const { valid, payload, failure, retryAfter } = await fipsign.verify(token)
if (!valid && failure === 'rejected') return res.status(401).end()          // the token is bad
if (!valid) return res.status(503).set('Retry-After', String(retryAfter ?? 5)).end()  // not the token's fault
```

`fipsign.middleware()` (Express / Fastify) does this for you: 401 for a refused token, 503 (with `Retry-After` when known) for the rest.

## When mandate.verify() says no

`mandate.verify()` never throws either. When `result` is `'denied'`, `failure` says whether FIPSign decided or the answer never arrived:

| `failure` | Meaning | Anything consumed? | What to do |
|---|---|---|---|
| `'rejected'` | FIPSign refused the call; `reason` says why (scope, budget, expired, revoked, suspended, agent signature, ...) | No | Do not act |
| `'rate_limited'` | Too many requests in the current minute | No | Wait `retryAfter` seconds and try again |
| `'quota_exhausted'` | Free tokens and packs used up | No | Buy a pack from the dashboard |
| `'unavailable'` | FIPSign answered but could not check the call (for example, an invalid API key) | No | Do not act; fix the cause |
| `'outcome_unknown'` | No usable answer (timeout, network, server error). The call may have been granted and charged | Maybe | Do not act on it and do not repeat it blindly (below) |

```typescript
const check = await fipsign.mandate.verify(token, 'send_email', 1, { agentSignature })
if (check.result === 'granted') return sendEmail()
if (check.failure === 'outcome_unknown') {
  // With an agentSignature: send the SAME call again while the signature is still valid.
  //   granted = it is applied now, once; agent_signature_replayed = it was applied the first time (do the action).
  // Without one: compare budgetConsumed of mandate.get(id) with the value you had before the call.
}
```

The SDK never repeats a call by itself: FIPSign does not recognise a repeated request. Details: Mandate 02c in the [guide](https://fipsign.dev/guide).

## Check the revocation list of your CA

`ca.getCrl()` returns the certificates your CA has revoked, and the list is signed by the CA (ML-DSA-65). `ca.verifyCrl()` checks that signature offline, so a list that was altered on the way, or that belongs to another CA, is not taken as good:

```typescript
const list  = await fipsign.ca.getCrl()
const check = await fipsign.ca.verifyCrl(list, rootCert)  // the CA_ROOT you saved when the CA was created (a PEM string for an X.509 CA)
if (!check.valid) throw new Error(check.error)
if (fipsign.ca.isCertRevoked(cert, list.crl)) throw new Error('revoked')
```

The signature covers `generatedAt`, so an old list cannot pass as a new one, but a correctly signed old list is still valid: `check.generatedAt` tells you when it was made, and how old a list you accept is up to you. Details: the CA chapter of the [guide](https://fipsign.dev/guide).

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens rely on ECDSA or RSA — both breakable by Shor's algorithm on a sufficiently powerful quantum computer. ML-DSA-65 is based on lattice problems (Module-LWE / Module-SIS) with no known quantum speedup. Standardized by NIST in August 2024 as FIPS 204.

---

## Links

- 📖 [Developer guide — full API reference, error codes, webhooks, CA/X.509](https://fipsign.dev/guide)
- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)