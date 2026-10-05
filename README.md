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

## Prove what an agent was allowed to do

FIPSign keeps a log of everything that happens to a mandate (emitted, each call it granted or denied, narrowed, suspended, resumed, revoked) and signs it. Pass your own id as `correlationId` (a ticket, a request id) to find an event later, and ask for a **receipt** on the calls you may have to prove:

```typescript
const { mandate, receipt } = await fipsign.mandate.emit({ /* ... */, correlationId: 'ticket-4821' })
const check = await fipsign.mandate.verify(mandate.token, 'send_reply', 1, { receipt: true, correlationId: 'req-77' })  // check.receipt
const done  = await fipsign.mandate.revoke(mandate.id, { correlationId: 'ticket-4822' })                                // done.receipt
```

`emit()` and the changes (`narrow`, `suspend`, `resume`, `revoke`) always return a receipt; `verify()` returns one when you pass `receipt: true`, granted or denied. Keep it next to your own record. It is FIPSign's signature over that event and over everything the log held before it, so the history cannot be rewritten later without the receipt showing it. Check it on your own machine, with no network:

```typescript
import { publicKeyFingerprint, verifyMandateReceipt } from 'fipsign-sdk'

// Once, the day you integrate. `publicKey` is the answer of:  curl -H "X-API-Key: pqa_your_api_key" https://api.fipsign.dev/public-key
// Save it (or just its fingerprint):
const fingerprint = await publicKeyFingerprint(publicKey)

// Any day later:
const { valid, problems } = await verifyMandateReceipt(receipt, { publicKey })
if (!valid) console.error(problems)
```

A project that rotated its keys has more than one: a receipt is checked with the key that made it. Pin the fingerprint you saved and let `mandate.publicKeys()` (every key the project has had, the retired ones too) supply the keys; a key is accepted only if its own fingerprint is the one you pinned:

```typescript
const { keys } = await fipsign.mandate.publicKeys()
const { valid, problems } = await verifyMandateReceipt(receipt, { pinFingerprint: fingerprint, keys })
```

Read the log, one mandate or the whole project:

```typescript
for await (const e of fipsign.mandate.eventsAll(mandate.id)) console.log(e.seq, e.type, JSON.parse(e.body))
const { events } = await fipsign.mandate.queryEvents({ correlationId: 'ticket-4821' })       // also: type, action, keyId, traceId, from, to
for await (const e of fipsign.mandate.queryEventsAll({ type: 'verify_denied' })) console.log(e.mandateId, e.at)
```

Export the whole log of a mandate and check it, with no network:

```typescript
import { verifyMandateExport } from 'fipsign-sdk'

const pages = await fipsign.mandate.exportAll(mandate.id)
const check = await verifyMandateExport(pages, { pinFingerprint: fingerprint })   // or { publicKey }
console.log(check.valid, check.complete, check.problems)
```

| Field | Meaning |
|---|---|
| `valid` | Every event follows the one before it and is what it says it is, and every signature that is in the export verifies. `problems` lists what does not |
| `complete` | The log starts at event 1 and ends in a checkpoint that seals everything before it. A log that is `valid` but not `complete` has events at its end that only the signed head (or a receipt you hold) protects |
| `keyTrust` | `'pinned'`: the key was fixed by you (`publicKey` or `pinFingerprint`). `'fipsign'`: you gave neither, so the keys came from FIPSign (`mandate.verifyReceipt()` and `mandate.verifyExport()` only): that detects a log that was altered, but not a key that FIPSign itself replaced |

`verifyMandateReceipt()` and `verifyMandateExport()` never throw and need no API key. A signature proves what FIPSign recorded and when; it does not prove that your service made the request. Events are kept for 365 days.

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