# fipsign-sdk

Post-quantum signing SDK for Node.js and the browser.

Signs and verifies any payload using **ML-DSA-65** (NIST FIPS 204) — the post-quantum digital signature standard resistant to Shor's algorithm. Standardized by NIST in August 2024.

**Not just for auth.** Sign users, orders, documents, devices, events — any entity that needs a tamper-proof, quantum-resistant signature.

---

## Install

```bash
npm install fipsign-sdk
```

---

## Quick start

**1.** Create a free account at [app.fipsign.dev](https://app.fipsign.dev)
— enter your email, verify the OTP code sent to your inbox.

**2.** In the dashboard, create a project, then create an API key inside that project.
Save the key — it will not be shown again.

**3.** Use the key in your app:

```typescript
import { PQAuth } from 'fipsign-sdk'

const fipsign = new PQAuth('pqa_your_api_key')
```

---

## sign() — Sign anything

The only required field is `sub` — any string identifying the entity you want to sign. All other fields are stored in the payload and returned on verify. Cost: 1 token.

```typescript
// Sign a user session
const { token, meta, usage } = await fipsign.sign({
  sub:              'user_123',
  email:            'user@example.com',
  role:             'admin',
  expiresInSeconds: 3600,           // optional, default 1 hour
})

// Sign an order
const { token } = await fipsign.sign({
  sub:      'order_456',
  amount:   299.99,
  currency: 'USD',
})

// Sign a document
const { token } = await fipsign.sign({
  sub:      'doc_789',
  hash:     'sha256:abc...',
  signedBy: 'alice',
})

// Sign a device
const { token } = await fipsign.sign({
  sub:      'device_iot_001',
  firmware: '2.1.4',
})

// Monitor quota and token source
console.log(`${usage.freeRemaining} free tokens remaining this month`)
console.log(`${usage.packRemaining} pack tokens remaining`)
console.log(`${usage.totalRemaining} total remaining`)
console.log(`charged from: ${meta.source}`) // "free" | "pack" | "free+pack"
```

### sign() response shape

```typescript
{
  token: {
    payload:   string,  // base64 encoded payload
    signature: string,  // ML-DSA-65 signature
    algorithm: string,  // "ML-DSA-65"
    issuedAt:  number,  // Unix timestamp
  },
  meta: {
    algorithm:        string,  // "ML-DSA-65"
    standard:         string,  // "NIST FIPS 204"
    quantumResistant: boolean,
    expiresIn:        number,  // seconds, as passed to sign()
    issuedFor:        string,  // your developer account email
    projectId:        string,
    tokenCost:        number,  // always 1
    source:           string,  // "free" | "pack" | "free+pack"
  },
  usage: {
    freeRemaining:  number,
    packRemaining:  number,
    totalRemaining: number,
    month:          string,  // e.g. "2026-05"
  }
}
```

---

## verify() — Verify a token

Never throws. Returns `{ valid, payload }` or `{ valid: false, error }`. Cost: 1 token.

```typescript
const { valid, payload } = await fipsign.verify(token)

if (!valid) {
  return res.status(401).json({ error: 'Unauthorized' })
}

console.log(payload.sub)   // 'user_123' (or 'order_456', 'doc_789', etc.)
console.log(payload.exp)   // expiry timestamp (Unix)
console.log(payload.iat)   // issued at timestamp (Unix)
// All custom fields passed to sign() are available on payload too
```

---

## verify() local — Offline, ~1ms

Enable `localVerify` to verify tokens entirely in memory — no API call, no network latency, no token cost.

```typescript
const fipsign = new PQAuth({
  apiKey:      'pqa_your_api_key',
  localVerify: true,
})

// Optional: preload public key at startup to avoid first-request latency
await fipsign.preloadPublicKey()

const { valid, payload, local } = await fipsign.verify(token)
console.log(local) // true — verified without an API call
```

**Important:** local verification does not check the revocation list. A revoked token will pass local verification if its signature is valid and it has not expired. Use remote verification for sensitive operations (payments, admin actions, etc.).

When server keys are rotated, the SDK automatically detects the mismatch, refreshes the cached key, and retries — no action needed on your end.

---

## revoke() — Revoke a token

Immediately and permanently invalidates a token. Future `verify()` calls will reject it even if the signature is valid and it hasn't expired. Cost: 1 token.

```typescript
await fipsign.revoke(token, 'user logged out')
await fipsign.revoke(token, 'order cancelled')
await fipsign.revoke(token, 'suspicious activity detected')
```

Revoking an already-revoked token returns success without consuming an extra token — the operation is idempotent.

> **Note:** Calling `revoke()` on an already-expired token returns a 400 error. Expired tokens cannot be submitted for revocation.

---

## middleware() — Express / Fastify

Reads `Authorization: Bearer <token>` and attaches the decoded payload to `req.user`. Returns 401 automatically on invalid tokens. Node.js only.

```typescript
import express from 'express'
import { PQAuth } from 'fipsign-sdk'

const app     = express()
const fipsign = new PQAuth('pqa_your_api_key')

app.use(express.json())

// Login — sign a token and return it base64-encoded to the client
app.post('/login', async (req, res) => {
  const user = await db.users.findByEmail(req.body.email)
  if (!user || !checkPassword(req.body.password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const { token } = await fipsign.sign({
    sub:              user.id,
    email:            user.email,
    role:             user.role,
    expiresInSeconds: 3600,
  })

  // Encode to base64 — this is what the client puts in Authorization: Bearer <encoded>
  const encoded = Buffer.from(JSON.stringify(token)).toString('base64')
  res.json({ token: encoded })
})

// Logout — decode the header and revoke the token immediately
app.post('/logout', async (req, res) => {
  const header = req.headers['authorization'] ?? ''
  if (header.startsWith('Bearer ')) {
    try {
      const token = JSON.parse(Buffer.from(header.slice(7), 'base64').toString('utf8'))
      await fipsign.revoke(token, 'user logged out')
    } catch { /* ignore malformed token */ }
  }
  res.json({ success: true })
})

// Protect all routes under /api with the FIPSign middleware
app.use('/api', fipsign.middleware())

// req.user is the verified payload — sub, email, role, exp, iat, etc.
app.get('/api/profile', (req, res) => {
  res.json({ user: req.user })
})

app.listen(3000)
```

---

## usage() — Token balance

Free tokens reset on the 1st of each month (UTC). Pack tokens never expire and accumulate across purchases. No token cost.

```typescript
const { current, monthlyHistory, packs, developer } = await fipsign.usage()

// Current balance
console.log(`Month: ${current.month}`)                          // e.g. "2026-05"
console.log(`Free:  ${current.freeRemaining} / ${current.freeLimit}`)
console.log(`Used:  ${current.freeUsed} this month`)
console.log(`Pack:  ${current.packRemaining}`)
console.log(`Total: ${current.totalRemaining}`)
console.log(`Account: ${developer.email}`)

// 6-month history (always 6 entries, months with no activity show 0)
monthlyHistory.forEach(({ month, tokensUsed, fromFree, fromPack }) => {
  console.log(`${month}: ${tokensUsed} used (${fromFree} free + ${fromPack} pack)`)
})

// Purchased packs
packs.forEach(({ id, packType, tokensPurchased, purchasedAt, paymentRef }) => {
  console.log(`${packType}: ${tokensPurchased} tokens — ${new Date(purchasedAt * 1000).toLocaleDateString()}`)
  console.log(`  id: ${id} — paymentRef: ${paymentRef ?? 'n/a'}`)
})
```

---

## health() — Service status

```typescript
const { status, algorithm, quantumResistant, version } = await fipsign.health()
console.log(status)           // "ok"
console.log(algorithm)        // "ML-DSA-65"
console.log(quantumResistant) // true
console.log(version)          // e.g. "2.0.0"
```

---

## webhooks — Real-time notifications

**Events:** `token.signed` · `token.rejected` · `token.revoked` · `limit.warning` · `limit.reached`

```typescript
// Register
const { webhook } = await fipsign.webhooks.register({
  url:    'https://yourapp.com/webhooks/fipsign',
  events: ['limit.warning', 'limit.reached', 'token.revoked'],
})

// Store webhook.secret securely — it won't be shown again
console.log(webhook.secret)

// Send a test event to confirm your endpoint is reachable
await fipsign.webhooks.test()

// Get current config (secret is never returned after registration)
const { webhook: config } = await fipsign.webhooks.get()
// config is null if no webhook has been registered yet
if (!config) console.log('No webhook configured')

// Delete
await fipsign.webhooks.delete()
```

Re-registering an existing webhook updates the URL and events but preserves the original secret. To rotate the secret, delete and re-register.

### Webhook event payloads

Each incoming POST has a top-level `event` string and a `data` object. The fields available in `data` depend on the event type:

**`token.signed`**
```typescript
{
  sub:            string,   // subject passed to sign()
  email:          string | null,
  role:           string | null,
  projectId:      string,
  apiKeyName:     string,
  tokensUsed:     number,
  freeRemaining:  number,
  packRemaining:  number,
  totalRemaining: number,
  source:         string,   // "free" | "pack" | "free+pack"
  month:          string,   // e.g. "2026-05"
}
```

**`token.rejected`**
```typescript
{
  reason:     string,         // why verification failed
  sub:        string | null,  // subject extracted from payload (if decodable)
  projectId:  string,
  apiKeyName: string,
}
```

**`token.revoked`**
```typescript
{
  sub:            string,
  reason:         string,
  apiKeyName:     string,
  projectId:      string,
  freeRemaining:  number,
  packRemaining:  number,
  totalRemaining: number,
}
```

**`limit.warning`** — fired when free tokens drop below 20% of monthly limit
```typescript
{
  freeRemaining:  number,
  freeLimit:      number,   // always 10000
  packRemaining:  number,
  totalRemaining: number,
  percentUsed:    number,   // e.g. 82
  month:          string,
  apiKeyName:     string,
}
```

**`limit.reached`** — fired when free tokens are exhausted and no pack is available
```typescript
{
  freeRemaining:  number,   // always 0
  packRemaining:  number,
  totalRemaining: number,
  month:          string,
  apiKeyName:     string,
}
```

### Verifying incoming webhook requests

Each incoming POST includes the headers `X-PQAuth-Event`, `X-PQAuth-Signature` (sha256=...), and `X-PQAuth-Timestamp`.

```typescript
import crypto from 'crypto'

app.post('/webhooks/fipsign', express.json(), (req, res) => {
  const sig      = req.headers['x-pqauth-signature'] as string
  const expected = 'sha256=' + crypto
    .createHmac('sha256', process.env.FIPSIGN_WEBHOOK_SECRET!)
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

## ca — Certificate Authority

Issue and verify post-quantum certificates for devices, services, or any entity that needs a tamper-proof identity. Built on ML-DSA-65 — the same algorithm used for token signing.

**Typical use case:** A manufacturer of smart locks, IoT sensors, or logistics devices creates a CA root once per project from the dashboard. For each device manufactured, the system calls `ca.issue()` with the device's public key. The device stores its certificate. Verification happens entirely offline — no API call needed at runtime.

**Setup:** Create a project in the dashboard, then click "Create CA" inside that project. Choose a certificate format:

- **PQCert** — FIPSign's native JSON format. Certificates are JSON objects verified with `ca.verifyCert()`. Simpler to work with in JavaScript/TypeScript environments.
- **X.509** — Standard X.509 v3 PEM certificates signed with ML-DSA-65 (OID `2.16.840.1.101.3.4.3.18`, RFC 9881). Compatible with OpenSSL 3.5+, standard PKI tooling, and enterprise infrastructure. Verified with `ca.verifyX509Cert()`.

The format is chosen once at CA creation and applies to all certificates issued by that CA. One CA per project — you cannot mix formats within a project.

> **Save the root certificate now.** It is shown only once and cannot be retrieved again. Without it, offline verification is not possible for any certificate issued by this CA. Store it in a secrets manager or secure file — treat it like a private key.

**One CA per project.** Each project can have one root CA. The CA is created once from the dashboard — no API call needed for setup.

When you call `ca.issue()`, `ca.getCrl()`, or other CA methods, the SDK automatically uses the CA associated with the project that owns the API key. No `caId` parameter needed.

---

### generateKeyPair() — Generate a key pair for a device

Generate an ML-DSA-65 key pair. The device keeps the `secretKey` and passes the `publicKey` to `ca.issue()`. Works for both PQCert and X.509 CAs.

```typescript
import { generateKeyPair } from 'fipsign-sdk'

const { publicKey, secretKey } = await generateKeyPair()
// store secretKey securely on the device — never send it to the server
// pass publicKey to ca.issue() to obtain a certificate
```

---

### ca.issue() — Issue a certificate

Issue a certificate signed by your project's CA. Cost: 1 token.

`expiresInSeconds` is required for both PQCert and X.509 CAs, and must be between 60 seconds (minimum) and 157,680,000 seconds (5 years maximum).

The shape of `certificate` in the response depends on the CA format of your project:

- **PQCert CA** — `certificate` is a `PQCert` JSON object with fields like `.id`, `.caId`, `.signature`, `.expiresAt`.
- **X.509 CA** — `certificate` is a PEM string (`"-----BEGIN CERTIFICATE-----\n..."`). Certificate metadata is available in `meta`.

```typescript
// PQCert CA
const { certificate, meta } = await fipsign.ca.issue({
  subject:          'device-serial-00123',
  publicKey:        devicePublicKey,
  expiresInSeconds: 365 * 24 * 60 * 60,
  meta:             { model: 'lock-v2', batch: '2026-05' },
})

// certificate is a PQCert object
console.log(certificate.id)        // cert_...
console.log(certificate.caId)      // ca_... — the CA that signed it
console.log(certificate.expiresAt) // Unix timestamp
console.log(meta.certId)           // same as certificate.id
console.log(meta.caId)             // ca_...
console.log(meta.subject)          // 'device-serial-00123'
console.log(meta.format)           // 'pqcert'
console.log(meta.issuedAt)         // Unix timestamp
console.log(meta.expiresAt)        // Unix timestamp
console.log(meta.algorithm)        // 'ML-DSA-65'
console.log(meta.standard)         // 'NIST FIPS 204'


// X.509 CA
const { certificate, meta } = await fipsign.ca.issue({
  subject:          'device-serial-00123',
  publicKey:        devicePublicKey,
  expiresInSeconds: 365 * 24 * 60 * 60,
})

// certificate is a PEM string
console.log(typeof certificate)    // "string"
console.log(certificate)           // "-----BEGIN CERTIFICATE-----\n..."
console.log(meta.certId)           // cert_... — use this for revocation
console.log(meta.caId)             // ca_...
console.log(meta.subject)          // 'device-serial-00123'
console.log(meta.format)           // 'x509'
console.log(meta.issuedAt)         // Unix timestamp
console.log(meta.expiresAt)        // Unix timestamp
console.log(meta.algorithm)        // 'ML-DSA-65'
console.log(meta.standard)         // 'NIST FIPS 204'
```

> **Note for X.509:** The `meta.certId` returned by `ca.issue()` is what you need for `ca.revokeCert()` and `ca.isCertRevoked()`. Store it alongside the PEM certificate.

> **Note for X.509:** The `meta` option (custom key-value pairs) is supported for PQCert CAs only. Passing `meta` when using an X.509 CA returns a 400 error — custom attributes should be encoded in the certificate `subject` or stored separately in your own database.

---

### ca.verifyCert() — Verify a PQCert certificate offline

Verify a **PQCert** certificate entirely in memory using the CA root certificate. No API call — uses ML-DSA-65 locally. Does not check revocation.

For X.509 certificates use `ca.verifyX509Cert()` instead.

```typescript
import rootCert from './root-cert.json' assert { type: 'json' }

const result = fipsign.ca.verifyCert(deviceCert, rootCert)

if (!result.valid) {
  console.error(result.error) // 'Invalid certificate signature', 'CERT_EXPIRED', etc.
  return reject('Device not authorized')
}

console.log(result.cert.subject)   // 'device-serial-00123'
console.log(result.cert.expiresAt) // Unix timestamp
```

---

### ca.verifyX509Cert() — Verify an X.509 certificate offline

Verify an **X.509** PEM certificate entirely in memory using the root CA PEM. No API call — parses the DER locally and verifies the ML-DSA-65 signature. Does not check revocation.

Never throws — always returns `{ valid, cert? }` or `{ valid: false, error }`.

For PQCert certificates use `ca.verifyCert()` instead.

```typescript
// rootCertPem is the PEM string shown at CA creation — save it once
const result = await fipsign.ca.verifyX509Cert(deviceCertPem, rootCertPem)

if (!result.valid) {
  // Possible error messages:
  //   'Certificate has expired'
  //   'Invalid certificate signature — not signed by this root CA'
  //   'Unsupported signature algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
  //   'Unsupported root CA algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
  console.error(result.error)
  return reject('Device not authorized')
}

// result.cert is the PEM string of the verified certificate
console.log(result.cert) // "-----BEGIN CERTIFICATE-----\n..."
```

---

### ca.isCertRevoked() — Check revocation offline

Check if a certificate appears in a CRL. Offline — pass the result of `ca.getCrl()`.

Accepts either a **PQCert object** (for PQCert CAs) or a **certId string** (for X.509 CAs). The `certId` is returned in `meta.certId` from `ca.issue()`.

```typescript
const { crl } = await fipsign.ca.getCrl()

// PQCert CA — pass the certificate object
if (fipsign.ca.isCertRevoked(deviceCert, crl)) {
  return reject('Device certificate has been revoked')
}

// X.509 CA — pass the certId string from meta
if (fipsign.ca.isCertRevoked(meta.certId, crl)) {
  return reject('Device certificate has been revoked')
}
```

---

### ca.getCrl() — Get the Certificate Revocation List

Fetch the current CRL for your project's CA. Free — no token cost.

The returned `crl` is always a flat `CrlEntry[]` array regardless of CA format — the SDK normalizes the response automatically. For X.509 CAs, the full signed CRL object (including the ML-DSA-65 signature) is also available in the `raw` field if you need to verify the CRL signature independently.

Use `getCrl()` when you need to verify revocation status offline or in bulk — download the list once and check multiple certificates against it locally using `isCertRevoked()`. For checking the status of a single certificate in real time (e.g. before a high-value transaction), use `getCert()` instead.

```typescript
const { caId, subject, crl, generatedAt, raw } = await fipsign.ca.getCrl()

console.log(`CA: ${subject}`)
console.log(`${crl.length} revoked certificates`)

crl.forEach(({ certId, revokedAt, reason }) => {
  // reason may be null if no reason was provided at revocation time
  console.log(`${certId} — revoked ${new Date(revokedAt * 1000).toISOString()} — ${reason ?? 'no reason'}`)
})

// X.509 CAs only: raw contains the full signed CRL object with ML-DSA-65 signature
// raw is undefined for PQCert CAs
if (raw) {
  console.log(raw.signature) // base64 ML-DSA-65 signature over the CRL
}
```

---

### ca.getCert() — Get a certificate by ID

Retrieve a certificate and its current status directly from the server. Use this when you need the real-time revocation status of a specific certificate — for example, before authorizing a high-value operation. Free — no token cost.

```typescript
const { certificate, status, meta } = await fipsign.ca.getCert('cert_...')

console.log(status.revoked)   // boolean
console.log(status.expired)   // boolean
console.log(status.revokedAt) // Unix timestamp or null
console.log(status.expiresAt) // Unix timestamp

// For PQCert CAs, certificate is a PQCert object
// For X.509 CAs, certificate is a PEM string
// For X.509 CAs, meta contains additional fields:
if (meta) {
  console.log(meta.certId)    // cert_...
  console.log(meta.caId)      // ca_...
  console.log(meta.subject)   // 'device-serial-00123'
  console.log(meta.format)    // 'x509'
  console.log(meta.algorithm) // 'ML-DSA-65'
}
```

---

### ca.revokeCert() — Revoke a certificate

Revoke a certificate immediately. It will appear in the CRL from this point on. Cost: 1 token.

```typescript
const { certId, revokedAt, reason, usage } = await fipsign.ca.revokeCert(
  'cert_...',
  'device decommissioned'
)

console.log(certId)              // cert_...
console.log(revokedAt)           // Unix timestamp
console.log(reason)              // 'device decommissioned' (or null if omitted)
console.log(usage.freeRemaining) // tokens remaining after this operation
```

---

### Full device lifecycle — PQCert

```typescript
import { PQAuth, generateKeyPair } from 'fipsign-sdk'
import rootCert from './root-cert.json' assert { type: 'json' }

const fipsign = new PQAuth('pqa_your_api_key')

// 1. Factory: generate a key pair for the device
const { publicKey, secretKey } = await generateKeyPair()

// 2. Factory: issue a certificate for the device
const { certificate } = await fipsign.ca.issue({
  subject:          'lock-serial-00123',
  publicKey,
  expiresInSeconds: 365 * 24 * 60 * 60,
  meta:             { model: 'lock-v3', batch: '2026-05' },
})
// store certificate (PQCert JSON object) and secretKey on the device

// 3. At runtime: verify the device certificate offline
const result = fipsign.ca.verifyCert(certificate, rootCert)
if (!result.valid) return reject(result.error)

// 4. At runtime: check the device is not revoked
const { crl } = await fipsign.ca.getCrl()
if (fipsign.ca.isCertRevoked(certificate, crl)) return reject('Device revoked')

// 5. Decommission: revoke the certificate
await fipsign.ca.revokeCert(certificate.id, 'device decommissioned')
```

---

### Full device lifecycle — X.509

```typescript
import { PQAuth, generateKeyPair } from 'fipsign-sdk'

const fipsign = new PQAuth('pqa_your_api_key')

// rootCertPem — the PEM string shown once at CA creation, stored securely
const rootCertPem = process.env.ROOT_CERT_PEM

// 1. Factory: generate a key pair for the device
const { publicKey, secretKey } = await generateKeyPair()

// 2. Factory: issue a certificate for the device
const { certificate: certPem, meta } = await fipsign.ca.issue({
  subject:          'lock-serial-00123',
  publicKey,
  expiresInSeconds: 365 * 24 * 60 * 60,
})
// store certPem (PEM string), meta.certId, and secretKey on the device

// 3. At runtime: verify the device certificate offline
const result = await fipsign.ca.verifyX509Cert(certPem, rootCertPem)
if (!result.valid) return reject(result.error)

// 4. At runtime: check the device is not revoked
const { crl } = await fipsign.ca.getCrl()
if (fipsign.ca.isCertRevoked(meta.certId, crl)) return reject('Device revoked')

// 5. Decommission: revoke the certificate using the certId from meta
await fipsign.ca.revokeCert(meta.certId, 'device decommissioned')
```

---

## Error handling

`verify()` and `ca.verifyX509Cert()` never throw — they always return `{ valid, ... }` or `{ valid: false, error }`.
All other methods throw `PQAuthError` on failure.

```typescript
import { PQAuth, PQAuthError } from 'fipsign-sdk'

try {
  await fipsign.sign({ sub: 'user_123' })
} catch (err) {
  if (err instanceof PQAuthError) {
    switch (err.code) {
      case 'INVALID_API_KEY':       // key format invalid — must be pqa_ + 64 hex chars
        break
      case 'API_ERROR':             // server returned an error (check err.status)
        break
      case 'TIMEOUT':               // request exceeded timeout (default: 10s)
        break
      case 'NETWORK_ERROR':         // connection failed
        break
      case 'MISSING_SUB':           // sign() called without sub
        break
      case 'INVALID_SIGNATURE':     // local verify: token tampered
        break
      case 'TOKEN_EXPIRED':         // local verify: token expired
        break
      case 'UNSUPPORTED_ALGORITHM': // local verify: unknown algorithm
        break
      case 'INVALID_CERT_TYPE':       // ca.verifyCert(): expected CA_ROOT or CA_CERT
        break
      case 'CA_MISMATCH':             // ca.verifyCert(): cert was not issued by this CA
        break
      case 'CERT_EXPIRED':            // ca.verifyCert(): certificate has expired
        break
      case 'INVALID_CERT_SIGNATURE':  // ca.verifyCert(): signature invalid
        break
    }
    console.error(err.code, err.message, err.status)
  }
}
```

---

## Token quota

Every account gets **10,000 free tokens per month**, reset on the 1st (UTC). Unused free tokens do not carry over. Additional tokens are available as non-expiring packs, purchased from the dashboard.

Each of these operations costs **1 token**: signing (`/sign`), verification (`/verify`), revocation (`/revoke`), certificate issuance (`/ca/issue`), and certificate revocation (`/ca/revoke`). Checking usage (`/usage`), fetching the public key (`/public-key`), and all CA read operations (`/ca/crl`, `/ca/certificate/:id`) are free.

---

## Rate limits

300 requests per minute per API key on `/sign` and `/verify`. On excess the API returns HTTP 429.

CA operations (`/ca/issue`, `/ca/revoke`) are rate limited at 300 requests per minute per API key, consistent with `/sign` and `/verify`. Read operations (`/ca/crl`, `/ca/certificate/:id`) are not rate limited.

Token quota and rate limits are separate controls — check the error message to distinguish them:
- `"Rate limit exceeded"` → back off and retry with exponential backoff
- `"Token limit reached"` → purchase a pack from the dashboard, retrying won't help

---

## Constructor options

```typescript
const fipsign = new PQAuth({
  apiKey:      'pqa_...',                    // required — 68-character key (pqa_ + 64 hex chars)
  baseUrl:     'https://api.fipsign.dev',    // optional, override for self-hosting
  timeout:     10_000,                       // optional, ms (default: 10000)
  localVerify: false,                        // optional, in-memory verification (default: false)
})
```

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | string | — | Required. From the dashboard. Constructor throws `INVALID_API_KEY` immediately if the key does not match the format `pqa_` followed by 64 lowercase hex characters. |
| `baseUrl` | string | `https://api.fipsign.dev` | Override for local dev or self-hosted instances. |
| `timeout` | number | `10000` | Request timeout in ms. Throws `TIMEOUT` on exceeded. |
| `localVerify` | boolean | `false` | When true, `verify()` runs in memory using a cached public key (refreshed every hour). No API call, no token cost. Does not check revocation. |

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens use ECDSA or RSA — both vulnerable to Shor's algorithm running on a sufficiently powerful quantum computer. ML-DSA-65 is based on the hardness of lattice problems (Module-LWE / Module-SIS), which have no known quantum speedup. It was standardized by NIST in August 2024 as FIPS 204.

---

## Links

- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- Developer guide: [fipsign.dev/guide](https://fipsign.dev/guide)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- API health: [api.fipsign.dev/health](https://api.fipsign.dev/health)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)
