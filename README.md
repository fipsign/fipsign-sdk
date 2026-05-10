# pqauth-sdk

Post-quantum authentication SDK for Node.js and the browser.

Signs and verifies tokens using **ML-DSA-65** (NIST FIPS 204) — the post-quantum signature standard that resists attacks from quantum computers, including Shor's algorithm.

---

## Install

```bash
npm install pqauth-sdk
```

Get your free API key at [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)

```typescript
import { PQAuth } from 'pqauth-sdk'
const pqauth = new PQAuth('pqa_your_api_key')
```

---

## sign() — Sign a token

```typescript
const { token } = await pqauth.sign({
  sub:              'user_123',
  email:            'user@example.com',
  role:             'admin',
  expiresInSeconds: 3600
})
```

---

## verify() — Verify a token

Never throws. Returns `{ valid, payload }` or `{ valid: false, error }`.

```typescript
const { valid, payload } = await pqauth.verify(token)
if (!valid) return res.status(401).json({ error: 'Unauthorized' })
console.log(payload.sub, payload.email, payload.role)
```

---

## revoke() — Revoke a token

Immediately invalidates a token. Use on logout or security events.

```typescript
await pqauth.revoke(token, 'user logged out')
```

---

## middleware() — Express / Fastify middleware

```typescript
app.use('/api', pqauth.middleware())

app.get('/api/profile', (req, res) => {
  res.json({ user: req.user }) // payload attached automatically
})
```

---

## usage() — Monthly usage stats

```typescript
const { current } = await pqauth.usage()
console.log(`${current.count} / ${current.limit} tokens — ${current.remaining} remaining`)
```

---

## webhooks — Real-time event notifications

Events: `token.signed` · `token.rejected` · `token.revoked` · `limit.warning` · `limit.reached`

```typescript
// Register
const { webhook } = await pqauth.webhooks.register({
  url:    'https://yourapp.com/webhooks/pqauth',
  events: ['limit.warning', 'limit.reached', 'token.revoked']
})
console.log(webhook.secret) // store this to verify incoming requests

// Test
await pqauth.webhooks.test()

// Remove
await pqauth.webhooks.delete()
```

Verify incoming webhook requests:

```typescript
app.post('/webhooks/pqauth', (req, res) => {
  const sig      = req.headers['x-pqauth-signature']
  const expected = 'sha256=' + crypto
    .createHmac('sha256', process.env.PQAUTH_WEBHOOK_SECRET!)
    .update(JSON.stringify(req.body))
    .digest('hex')

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.status(401).send('Invalid signature')
  }

  const { event, data } = req.body
  console.log(`PQAuth event: ${event}`, data)
  res.status(200).send('ok')
})
```

---

## Full login + logout example

```typescript
import express from 'express'
import { PQAuth } from 'pqauth-sdk'

const app    = express()
const pqauth = new PQAuth('pqa_your_api_key')

app.post('/login', async (req, res) => {
  const user = await db.users.findByEmail(req.body.email)
  if (!user || !checkPassword(req.body.password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const { token } = await pqauth.sign({ sub: user.id, email: user.email, role: user.role })
  res.json({ token })
})

app.post('/logout', async (req, res) => {
  const token = getTokenFromRequest(req)
  if (token) await pqauth.revoke(token, 'user logged out')
  res.json({ success: true })
})

app.use('/api', pqauth.middleware())

app.get('/api/profile', (req, res) => {
  res.json({ user: req.user })
})
```

---

## Works with any identity provider

Google, GitHub, Apple, Particle Network, Auth0 — PQAuth sits after identity verification and secures the session token.

```typescript
app.post('/auth/callback', async (req, res) => {
  const { verifiedUser } = req.body
  const { token } = await pqauth.sign({ sub: verifiedUser.id, email: verifiedUser.email })
  res.json({ token })
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
    console.error(err.code)    // API_ERROR | TIMEOUT | NETWORK_ERROR | INVALID_API_KEY
    console.error(err.message)
    console.error(err.status)
  }
}
```

---

## Why ML-DSA-65?

JWT with RS256/ES256 and OAuth tokens sign with ECDSA or RSA — vulnerable to Shor's algorithm on quantum computers. ML-DSA-65 is based on lattice problems, resistant to all known quantum algorithms. Standardized by NIST in August 2024 as FIPS 204.

---

## Links

- Dashboard: [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)
- API status: [pqauth-core.gdbok.workers.dev/health](https://pqauth-core.gdbok.workers.dev/health)
- NIST FIPS 204: [csrc.nist.gov](https://csrc.nist.gov/pubs/fips/204/final)

---

## Local verification (offline, ~1ms)

By default `verify()` calls the API. Enable `localVerify` to verify tokens entirely in memory using the cached public key — no network call needed.

```typescript
// Enable local verification at construction
const pqauth = new PQAuth({
  apiKey:      'pqa_your_api_key',
  localVerify: true               // verify locally, no API call
})

// Optional: preload the public key at startup
// to avoid first-request latency
await pqauth.preloadPublicKey()

// verify() now runs in ~1ms with no network call
const { valid, payload, local } = await pqauth.verify(token)
console.log(local) // true — verified locally
```

**How it works:**
- On first `verify()`, the public key is fetched from the API and cached for 1 hour
- All subsequent verifications use the cached key — pure ML-DSA-65 in memory
- If keys are rotated (via `/admin/rotate-keys`), the SDK detects the mismatch and automatically refreshes the cache
- Revocation still requires an API call — `revoke()` is always online

**When to use local verification:**
- High-traffic endpoints where every millisecond counts
- Serverless functions where you want to minimize external calls
- Edge environments (Cloudflare Workers, Vercel Edge) where latency is critical

**Note:** local verification does not check the revocation blacklist. If you need revocation checking, use remote verification (default) or call `verify()` remotely on sensitive operations.
