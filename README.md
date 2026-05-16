# pqauth-sdk

Post-quantum signing SDK for Node.js and the browser.

Signs and verifies any payload using **ML-DSA-65** (NIST FIPS 204) — the post-quantum digital signature standard resistant to Shor's algorithm. Standardized by NIST in August 2024.

**Not just for auth.** Sign users, orders, documents, devices, events — any entity that needs a tamper-proof, quantum-resistant signature.

---

## Install

```bash
npm install pqauth-sdk
```

---

## Quick start

**1.** Create a free account at [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)
— enter your email, verify the OTP code sent to your inbox.

**2.** In the dashboard, create a project, then create an API key inside that project.
Save the key — it will not be shown again.

**3.** Use the key in your app:

```typescript
import { PQAuth } from 'pqauth-sdk'

const pqauth = new PQAuth('pqa_your_api_key')
```
---

## sign() — Sign anything

The only required field is `sub` — any string identifying the entity you want to sign. All other fields are stored in the payload and returned on verify.

```typescript
// Sign a user session
const { token, usage } = await pqauth.sign({
  sub:              'user_123',
  email:            'user@example.com',
  role:             'admin',
  expiresInSeconds: 3600,           // optional, default 1 hour
})

// Sign an order
const { token } = await pqauth.sign({
  sub:      'order_456',
  amount:   299.99,
  currency: 'USD',
})

// Sign a document
const { token } = await pqauth.sign({
  sub:      'doc_789',
  hash:     'sha256:abc...',
  signedBy: 'alice',
})

// Sign a device
const { token } = await pqauth.sign({
  sub:      'device_iot_001',
  firmware: '2.1.4',
})

// Monitor quota
console.log(`${usage.freeRemaining} free tokens remaining this month`)
console.log(`${usage.packRemaining} pack tokens remaining`)
console.log(`${usage.totalRemaining} total remaining`)
```

---

## verify() — Verify a token

Never throws. Returns `{ valid, payload }` or `{ valid: false, error }`.

```typescript
const { valid, payload } = await pqauth.verify(token)

if (!valid) {
  return res.status(401).json({ error: 'Unauthorized' })
}

console.log(payload.sub)   // 'user_123' (or 'order_456', 'doc_789', etc.)
console.log(payload.exp)   // expiry timestamp (Unix)
// All custom fields are available on payload too
```

---

## verify() local — Offline, ~1ms

Enable `localVerify` to verify tokens entirely in memory — no API call, no network latency.

```typescript
const pqauth = new PQAuth({
  apiKey:      'pqa_your_api_key',
  localVerify: true,
})

// Optional: preload public key at startup to avoid first-request latency
await pqauth.preloadPublicKey()

const { valid, payload, local } = await pqauth.verify(token)
console.log(local) // true — verified without an API call
```

**Important:** local verification does not check the revocation list. Use remote verification for sensitive operations (payments, admin actions, etc.).

When server keys are rotated, the SDK automatically detects the mismatch, refreshes the cached key, and retries — no action needed on your end.

---

## revoke() — Revoke a token

Immediately invalidates a token. Future `verify()` calls will reject it even if the signature is valid and it hasn't expired.

```typescript
await pqauth.revoke(token, 'user logged out')
await pqauth.revoke(token, 'suspicious activity detected')
```

---

## middleware() — Express / Fastify

Reads `Authorization: Bearer <token>` and attaches the decoded payload to `req.user`. Node.js only.

```typescript
import express from 'express'
import { PQAuth } from 'pqauth-sdk'

const app    = express()
const pqauth = new PQAuth('pqa_your_api_key')

app.use(express.json())

app.post('/login', async (req, res) => {
  const user = await db.users.findByEmail(req.body.email)
  if (!user || !checkPassword(req.body.password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const { token } = await pqauth.sign({ sub: user.id, email: user.email, role: user.role })
  const encoded = Buffer.from(JSON.stringify(token)).toString('base64')
  res.json({ token, encoded })
})

app.post('/logout', async (req, res) => {
  const token = getTokenFromRequest(req)
  if (token) await pqauth.revoke(token, 'user logged out')
  res.json({ success: true })
})

// Protect routes
app.use('/api', pqauth.middleware())

app.get('/api/profile', (req, res) => {
  res.json({ user: req.user })
})
```

---

## usage() — Token balance

Free tokens reset on the 1st of each month (UTC). Pack tokens never expire and accumulate across purchases.

```typescript
const { current, monthlyHistory, packs } = await pqauth.usage()

console.log(`Free: ${current.freeRemaining} / ${current.freeLimit}`)
console.log(`Pack: ${current.packRemaining}`)
console.log(`Total: ${current.totalRemaining}`)

// 6-month history
monthlyHistory.forEach(({ month, tokensUsed, fromFree, fromPack }) => {
  console.log(`${month}: ${tokensUsed} used (${fromFree} free + ${fromPack} pack)`)
})

// Purchased packs
packs.forEach(({ packType, tokensPurchased, purchasedAt }) => {
  console.log(`${packType}: ${tokensPurchased} tokens — ${new Date(purchasedAt * 1000).toLocaleDateString()}`)
})
```

---

## webhooks — Real-time notifications

**Events:** `token.signed` · `token.rejected` · `token.revoked` · `limit.warning` · `limit.reached`

```typescript
// Register
const { webhook } = await pqauth.webhooks.register({
  url:    'https://yourapp.com/webhooks/pqauth',
  events: ['limit.warning', 'limit.reached', 'token.revoked'],
})

// Store webhook.secret securely — it won't be shown again
console.log(webhook.secret)

await pqauth.webhooks.test()                    // send a test event
const { webhook: config } = await pqauth.webhooks.get()
await pqauth.webhooks.delete()
```

### Verifying incoming webhook requests

```typescript
import crypto from 'crypto'

app.post('/webhooks/pqauth', express.json(), (req, res) => {
  const sig      = req.headers['x-pqauth-signature'] as string
  const expected = 'sha256=' + crypto
    .createHmac('sha256', process.env.PQAUTH_WEBHOOK_SECRET!)
    .update(JSON.stringify(req.body))
    .digest('hex')

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.status(401).send('Invalid signature')
  }

  const { event, data } = req.body

  switch (event) {
    case 'limit.warning':
      console.warn(`Usage warning — ${data.freeRemaining} free tokens left this month`)
      break
    case 'limit.reached':
      console.error(`Limit reached — pack remaining: ${data.packRemaining}`)
      break
    case 'token.revoked':
      console.log(`Token revoked for sub: ${data.sub}`)
      break
  }

  res.status(200).send('ok')
})
```

---

## Error handling

```typescript
import { PQAuth, PQAuthError } from 'pqauth-sdk'

try {
  await pqauth.sign({ sub: 'user_123' })
} catch (err) {
  if (err instanceof PQAuthError) {
    switch (err.code) {
      case 'INVALID_API_KEY':       // bad or missing API key
      case 'API_ERROR':             // server returned an error (check err.status)
      case 'TIMEOUT':               // request exceeded timeout (default: 10s)
      case 'NETWORK_ERROR':         // connection failed
      case 'MISSING_SUB':           // sign() called without sub
      case 'INVALID_SIGNATURE':     // local verify: token tampered
      case 'TOKEN_EXPIRED':         // local verify: token expired
      case 'UNSUPPORTED_ALGORITHM': // local verify: unknown algorithm
    }
    console.error(err.code, err.message, err.status)
  }
}
```

---

## Token quota

Every account gets **10,000 free tokens per month**, reset on the 1st (UTC). Additional tokens are available as non-expiring packs, managed through the dashboard.

Each operation costs 1 token: signing (`/sign`), verification (`/verify`), and revocation (`/revoke`).

---

## Constructor options

```typescript
const pqauth = new PQAuth({
  apiKey:      'pqa_...',   // required
  baseUrl:     'https://pqauth-core.gdbok.workers.dev', // optional, override for self-hosting
  timeout:     10_000,      // optional, ms (default: 10000)
  localVerify: false,       // optional, enable in-memory verification (default: false)
})
```

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens use ECDSA or RSA — both vulnerable to Shor's algorithm running on a sufficiently powerful quantum computer. ML-DSA-65 is based on the hardness of lattice problems (Module-LWE / Module-SIS), which have no known quantum speedup. It was standardized by NIST in August 2024 as FIPS 204.

---

## Links

- Dashboard: [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)
- API status: [pqauth-core.gdbok.workers.dev/health](https://pqauth-core.gdbok.workers.dev/health)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)
