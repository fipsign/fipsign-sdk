# pqauth-sdk

Post-quantum authentication SDK for Node.js and the browser.

Signs and verifies tokens using **ML-DSA-65** (NIST FIPS 204) — the post-quantum signature standard that resists attacks from quantum computers, including Shor's algorithm.

---

## Install

```bash
npm install pqauth-sdk
```

## Setup

**1.** Create a free account at [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)

**2.** Create a project in the dashboard

**3.** Create an API key inside that project

**4.** Use the key in your app:

```typescript
import { PQAuth } from 'pqauth-sdk'

const pqauth = new PQAuth('pqa_your_api_key')
```

Each API key is linked to a project. Usage analytics are tracked per project in the dashboard.

---

## sign() — Sign a token

Call this after verifying your user's credentials.

```typescript
const { token } = await pqauth.sign({
  sub:              'user_123',          // required — userId or email
  email:            'user@example.com',  // optional
  role:             'admin',             // optional
  expiresInSeconds: 3600                 // optional, default 1 hour
})

// Send token to your frontend
res.json({ token })
```

---

## verify() — Verify a token

Never throws. Returns `{ valid, payload }` or `{ valid: false, error }`.

```typescript
const { valid, payload } = await pqauth.verify(token)

if (!valid) {
  return res.status(401).json({ error: 'Unauthorized' })
}

console.log(payload.sub)   // 'user_123'
console.log(payload.email) // 'user@example.com'
console.log(payload.role)  // 'admin'
```

---

## verify() local — Offline, ~1ms

Enable `localVerify` to verify tokens entirely in memory — no API call, no latency.

```typescript
const pqauth = new PQAuth({
  apiKey:      'pqa_your_api_key',
  localVerify: true
})

// Optional: preload public key at startup
await pqauth.preloadPublicKey()

// Verifies in ~1ms, no network call
const { valid, payload, local } = await pqauth.verify(token)
console.log(local) // true
```

**Note:** local verification does not check the revocation blacklist. Use remote verification on sensitive operations.

---

## revoke() — Revoke a token

Immediately invalidates a token. Future `verify()` calls will reject it even if the signature is valid.

```typescript
// On user logout
await pqauth.revoke(token, 'user logged out')

// On security event
await pqauth.revoke(token, 'suspicious activity detected')
```

---

## middleware() — Express / Fastify

Reads `Authorization: Bearer <token>` and attaches payload to `req.user`.

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

  const { token } = await pqauth.sign({
    sub:   user.id,
    email: user.email,
    role:  user.role,
  })

  res.json({ token })
})

app.post('/logout', async (req, res) => {
  const token = getTokenFromRequest(req)
  if (token) await pqauth.revoke(token, 'user logged out')
  res.json({ success: true })
})

// Protect all /api routes
app.use('/api', pqauth.middleware())

app.get('/api/profile', (req, res) => {
  res.json({ user: req.user })
})
```

---

## usage() — Monthly stats

```typescript
const { current } = await pqauth.usage()

console.log(`${current.count} / ${current.limit} tokens used this month`)
console.log(`${current.remaining} remaining`)
console.log(`Project: ${current.projectId}`)
```

Usage is tracked per project. You can see the full breakdown with charts in the dashboard.

---

## webhooks — Real-time notifications

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
import crypto from 'crypto'

app.post('/webhooks/pqauth', (req, res) => {
  const sig      = req.headers['x-pqauth-signature'] as string
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

## Works with any identity provider

Google, GitHub, Apple, Particle Network, Auth0 — PQAuth secures the session token after identity verification.

```typescript
// After Google / Particle / Auth0 verifies the user
app.post('/auth/callback', async (req, res) => {
  const { verifiedUser } = req.body

  const { token } = await pqauth.sign({
    sub:   verifiedUser.id,
    email: verifiedUser.email,
  })

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
