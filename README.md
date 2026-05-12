# pqauth-sdk

Post-quantum authentication SDK for Node.js and the browser.

Signs and verifies tokens using **ML-DSA-65** (NIST FIPS 204) — the post-quantum digital signature standard resistant to attacks from quantum computers, including Shor's algorithm. Standardized by NIST in August 2024.

---

## Install

```bash
npm install pqauth-sdk
```

---

## Quick start

**1.** Create a free account at [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)

**2.** On registration, a default project and its API key are created automatically. Save the key — it won't be shown again.

**3.** Use the key in your app:

```typescript
import { PQAuth } from 'pqauth-sdk'

const pqauth = new PQAuth('pqa_your_api_key')
```

---

## sign() — Sign a token

Call this after verifying your user's credentials. Each call counts against your monthly token quota.

```typescript
const { token, usage } = await pqauth.sign({
  sub:              'user_123',          // required — user ID
  email:            'user@example.com',  // optional
  role:             'admin',             // optional
  expiresInSeconds: 3600,               // optional, default 1 hour
})

// Send token to your frontend
res.json({ token })

// Monitor your quota
console.log(`${usage.remaining} tokens remaining this month`)
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
console.log(payload.exp)   // expiry timestamp (Unix)
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

**Important:** local verification does not check the revocation list. Use remote verification for sensitive operations (admin actions, payments, etc.).

When server keys are rotated, the SDK automatically detects the mismatch, refreshes the cached key, and retries — no action needed on your end.

---

## revoke() — Revoke a token

Immediately invalidates a token. Future `verify()` calls will reject it even if the signature is valid and it hasn't expired.

```typescript
// On logout
await pqauth.revoke(token, 'user logged out')

// On security event
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

// Login: verify credentials, then issue a PQAuth token
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

// Logout: revoke the token immediately
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

## usage() — Monthly quota

Usage is tracked globally per account. All projects share a single monthly pool defined by your plan. On the free plan, this is **10,000 tokens per month**.

```typescript
const { current, history } = await pqauth.usage()

console.log(`${current.count} / ${current.limit} tokens used`)
console.log(`${current.remaining} remaining — resets ${current.month}`)
console.log(`Plan: ${current.plan}`)

// 6-month history
history.forEach(({ month, count }) => {
  console.log(`${month}: ${count} tokens`)
})
```

---

## webhooks — Real-time notifications

Get notified when important events happen in your account.

**Events:** `token.signed` · `token.rejected` · `token.revoked` · `limit.warning` · `limit.reached`

```typescript
// Register a webhook endpoint
const { webhook } = await pqauth.webhooks.register({
  url:    'https://yourapp.com/webhooks/pqauth',
  events: ['limit.warning', 'limit.reached', 'token.revoked'],
})

// Store webhook.secret securely — you'll need it to verify incoming requests
console.log(webhook.secret)

// Send a test event
await pqauth.webhooks.test()

// Get current config
const { webhook: config } = await pqauth.webhooks.get()

// Remove webhook
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

  const { event, data, timestamp } = req.body

  switch (event) {
    case 'limit.warning':
      console.warn(`Usage warning: ${data.count}/${data.limit} tokens used`)
      break
    case 'limit.reached':
      console.error('Monthly token limit reached')
      break
    case 'token.revoked':
      console.log(`Token revoked for sub: ${data.sub}`)
      break
  }

  res.status(200).send('ok')
})
```

---

## Projects

Your account can have up to **5 projects** on the free plan. Each project gets its own API key, but all projects share the same monthly token pool.

Projects are managed through the dashboard or the API directly:

```typescript
// Projects are created and managed via the dashboard.
// Each project gets its own API key on creation.
// Deleting a project revokes its keys but does not affect your usage count.
```

---

## Works with any identity provider

PQAuth handles the token layer. You verify the user's identity however you want — then issue a post-quantum token.

```typescript
// After Google OAuth, Particle Network, Auth0, or your own login
app.post('/auth/callback', async (req, res) => {
  const { verifiedUser } = req.body  // from your auth provider

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
    switch (err.code) {
      case 'INVALID_API_KEY':  // bad or missing API key
      case 'API_ERROR':        // server returned an error (check err.status)
      case 'TIMEOUT':          // request exceeded timeout (default: 10s)
      case 'NETWORK_ERROR':    // connection failed
      case 'MISSING_SUB':      // sign() called without sub
      case 'INVALID_SIGNATURE': // local verify: token tampered
      case 'TOKEN_EXPIRED':    // local verify: token expired
      case 'UNSUPPORTED_ALGORITHM': // local verify: unknown algorithm
    }
    console.error(err.code, err.message, err.status)
  }
}
```

---

## Plans

| Feature | Free |
|---|---|
| Tokens / month | 10,000 |
| Projects | 5 |
| API keys | 5 (1 per project) |
| Webhooks | ✓ |
| Local verification | ✓ |
| Token revocation | ✓ |

Usage resets on the first of each month (UTC). Signing tokens (`/sign`) counts against your quota. Verification and revocation do not.

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
