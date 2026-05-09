# pqauth-sdk

Post-quantum authentication SDK for Node.js and the browser.

Signs and verifies tokens using **ML-DSA-65** (NIST FIPS 204) — the post-quantum signature standard that resists attacks from quantum computers.

---

## Install

```bash
npm install pqauth-sdk
```

## Quick start

Get your API key at [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)

```typescript
import { PQAuth } from 'pqauth-sdk'

const pqauth = new PQAuth('pqa_your_api_key')
```

---

## Sign a token

Call this after verifying your user's credentials. PQAuth signs the token — you handle the login.

```typescript
const { token } = await pqauth.sign({
  sub:   'user_123',           // required — userId or email
  email: 'juan@example.com',  // optional
  role:  'admin',             // optional
  expiresInSeconds: 3600      // optional, default 1 hour
})

// Send token to your frontend
res.json({ token })
```

---

## Verify a token

```typescript
const { valid, payload } = await pqauth.verify(token)

if (!valid) {
  return res.status(401).json({ error: 'Unauthorized' })
}

console.log(payload.sub)   // 'user_123'
console.log(payload.email) // 'juan@example.com'
console.log(payload.role)  // 'admin'
```

---

## Express middleware

Automatically reads the `Authorization: Bearer <token>` header and attaches the payload to `req.user`.

```typescript
import express from 'express'
import { PQAuth } from 'pqauth-sdk'

const app    = express()
const pqauth = new PQAuth('pqa_your_api_key')

// Protect all routes under /api
app.use('/api', pqauth.middleware())

app.get('/api/profile', (req, res) => {
  res.json({ user: req.user })
})
```

---

## Full example — Express login flow

```typescript
import express from 'express'
import { PQAuth } from 'pqauth-sdk'

const app    = express()
const pqauth = new PQAuth('pqa_your_api_key')

app.use(express.json())

// 1. Your login endpoint — verify credentials, then sign with PQAuth
app.post('/login', async (req, res) => {
  const { email, password } = req.body

  // Your existing auth logic
  const user = await db.users.findByEmail(email)
  if (!user || !checkPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  // Sign with PQAuth — quantum-resistant token
  const { token } = await pqauth.sign({
    sub:   user.id,
    email: user.email,
    role:  user.role,
  })

  res.json({ token })
})

// 2. Protected routes
app.use('/api', pqauth.middleware())

app.get('/api/profile', (req, res) => {
  res.json({ user: req.user })
})
```

---

## With social login (Google, Particle Network, etc.)

PQAuth works alongside any identity provider. The provider verifies the identity — PQAuth secures the session token.

```typescript
// After Google / Particle / Auth0 verifies the user
app.post('/auth/callback', async (req, res) => {
  const { googleUser } = req.body // verified by Google

  const { token } = await pqauth.sign({
    sub:   googleUser.id,
    email: googleUser.email,
    role:  'user',
  })

  res.json({ token })
})
```

---

## Health check

```typescript
const health = await pqauth.health()
// { status: 'ok', algorithm: 'ML-DSA-65', quantumResistant: true }
```

---

## Why ML-DSA-65?

Conventional auth systems (JWT with RS256/ES256, OAuth) sign tokens with ECDSA or RSA. These algorithms are vulnerable to Shor's algorithm, which runs efficiently on quantum computers.

ML-DSA-65 is based on lattice problems, which are resistant to all known quantum algorithms. It was standardized by NIST in August 2024 as FIPS 204.

---

## Error handling

```typescript
import { PQAuth, PQAuthError } from 'pqauth-sdk'

try {
  const { token } = await pqauth.sign({ sub: 'user_123' })
} catch (err) {
  if (err instanceof PQAuthError) {
    console.error(err.code)    // 'API_ERROR' | 'TIMEOUT' | 'NETWORK_ERROR'
    console.error(err.message) // Human-readable message
    console.error(err.status)  // HTTP status if applicable
  }
}
```

---

## API reference

### `new PQAuth(apiKey: string)`
### `new PQAuth(options: PQAuthOptions)`

| Option    | Type   | Default                                      | Description          |
|-----------|--------|----------------------------------------------|----------------------|
| `apiKey`  | string | —                                            | Your pqa_ API key    |
| `baseUrl` | string | `https://pqauth-core.gdbok.workers.dev`      | API base URL         |
| `timeout` | number | `10000`                                      | Timeout (ms)         |

### `pqauth.sign(options): Promise<SignResult>`
### `pqauth.verify(token): Promise<VerifyResult>`
### `pqauth.middleware(): RequestHandler`
### `pqauth.health(): Promise<HealthResult>`

---

## Links

- Dashboard: [pqauth-dashboard.pages.dev](https://pqauth-dashboard.pages.dev)
- API: [pqauth-core.gdbok.workers.dev](https://pqauth-core.gdbok.workers.dev)
- Standard: [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
