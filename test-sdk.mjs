/**
 * FIPSign SDK — Integration test
 * Runs against the live backend using the published fipsign-sdk
 *
 * Usage:
 *   FIPSIGN_API_KEY=pqa_...              \
 *   WEBHOOK_URL=https://webhook.site/... \
 *   WEBHOOK_SITE_TOKEN=your-uuid         \
 *   node test-sdk.mjs
 *
 * Optional:
 *   FIPSIGN_ROOT_CERT_JSON='$(cat root-cert.json)'   — enables offline verifyCert() tests
 *
 * Prerequisites:
 *   1. Create a free account at https://app.fipsign.dev
 *   2. Create a project and an API key inside that project
 *   3. Create a CA for that project from the dashboard
 *   4. Create a free endpoint at https://webhook.site and copy your UUID
 *   5. npm install fipsign-sdk
 */

import { PQAuth, PQAuthError } from 'fipsign-sdk'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

// ─── Required environment variables ───────────────────────────────────────────

const API_KEY            = process.env.FIPSIGN_API_KEY
const WEBHOOK_URL        = process.env.WEBHOOK_URL
const WEBHOOK_SITE_TOKEN = process.env.WEBHOOK_SITE_TOKEN

if (!API_KEY) {
  console.error('\x1b[31mError: FIPSIGN_API_KEY is required.\x1b[0m')
  console.error('Get your API key at https://app.fipsign.dev')
  process.exit(1)
}
if (!WEBHOOK_URL || !WEBHOOK_SITE_TOKEN) {
  console.error('\x1b[31mError: WEBHOOK_URL and WEBHOOK_SITE_TOKEN are required.\x1b[0m')
  console.error('Create a free endpoint at https://webhook.site and copy your UUID.')
  console.error('  WEBHOOK_URL=https://webhook.site/<your-uuid>')
  console.error('  WEBHOOK_SITE_TOKEN=<your-uuid>')
  process.exit(1)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const GREEN  = '\x1b[32m'
const RED    = '\x1b[31m'
const CYAN   = '\x1b[36m'
const DIM    = '\x1b[2m'
const RESET  = '\x1b[0m'
const BOLD   = '\x1b[1m'

let passed = 0
let failed = 0

function log(label, msg) {
  console.log('  ' + DIM + label.padEnd(32) + RESET + ' ' + msg)
}

function pass(name) {
  passed++
  console.log(GREEN + '  ✓' + RESET + ' ' + name)
}

function fail(name, err) {
  failed++
  console.log(RED + '  ✗' + RESET + ' ' + name)
  console.log('    ' + DIM + '→ ' + (err?.message ?? err) + RESET)
}

function section(title) {
  console.log('\n' + CYAN + BOLD + '── ' + title + RESET)
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function fromBase64(b64) {
  const binary = atob(b64)
  const bytes  = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// ─── Run ──────────────────────────────────────────────────────────────────────

async function run() {
  console.log('\n' + BOLD + 'FIPSign SDK — Integration Test' + RESET)
  console.log(DIM + 'fipsign-sdk · ' + new Date().toISOString() + RESET + '\n')

  const pq = new PQAuth(API_KEY)

  // ─── 01 Health ──────────────────────────────────────────────────────────────
  section('01 · Health check')
  try {
    const h = await pq.health()
    if (h.status !== 'ok')           throw new Error('status is "' + h.status + '", expected "ok"')
    if (h.algorithm !== 'ML-DSA-65') throw new Error('algorithm is "' + h.algorithm + '", expected "ML-DSA-65"')
    if (!h.quantumResistant)         throw new Error('quantumResistant is false')
    if (!h.version)                  throw new Error('missing version field')
    log('status',           h.status)
    log('algorithm',        h.algorithm)
    log('quantumResistant', String(h.quantumResistant))
    log('version',          h.version)
    pass('health() returns correct fields')
  } catch (err) { fail('health()', err) }

  // ─── 02 Invalid API key ──────────────────────────────────────────────────────
  section('02 · Invalid API key rejection')
  try {
    new PQAuth('bad_key')
    fail('constructor rejects bad key', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'INVALID_API_KEY') {
      pass('constructor throws PQAuthError(INVALID_API_KEY) for bad key')
    } else {
      fail('constructor rejects bad key', err)
    }
  }

  // ─── 03 sign() ───────────────────────────────────────────────────────────────
  section('03 · sign()')
  let userToken, orderToken, docToken

  try {
    const r = await pq.sign({ sub: 'user_test', email: 'test@example.com', role: 'admin', expiresInSeconds: 3600 })
    if (!r.token?.payload)   throw new Error('missing token.payload')
    if (!r.token?.signature) throw new Error('missing token.signature')
    if (r.token.algorithm !== 'ML-DSA-65') throw new Error('wrong algorithm: ' + r.token.algorithm)
    if (r.meta.tokenCost !== 1) throw new Error('tokenCost is ' + r.meta.tokenCost + ', expected 1')
    if (!['free', 'pack', 'free+pack'].includes(r.meta.source)) throw new Error('unexpected source: ' + r.meta.source)
    if (!r.meta.projectId)  throw new Error('missing meta.projectId')
    if (!r.meta.issuedFor)  throw new Error('missing meta.issuedFor')
    if (r.meta.expiresIn !== 3600) throw new Error('meta.expiresIn is ' + r.meta.expiresIn + ', expected 3600')
    if (typeof r.usage.freeRemaining !== 'number') throw new Error('missing usage.freeRemaining')
    if (typeof r.usage.packRemaining !== 'number') throw new Error('missing usage.packRemaining')
    if (typeof r.usage.totalRemaining !== 'number') throw new Error('missing usage.totalRemaining')
    if (!r.usage.month) throw new Error('missing usage.month')
    log('algorithm',     r.token.algorithm)
    log('tokenCost',     String(r.meta.tokenCost))
    log('source',        r.meta.source)
    log('expiresIn',     String(r.meta.expiresIn))
    log('usage.month',   r.usage.month)
    log('freeRemaining', String(r.usage.freeRemaining))
    userToken = r.token
    pass('sign() user session — correct shape and all fields present')
  } catch (err) { fail('sign() user session', err) }

  try {
    const r = await pq.sign({ sub: 'order_456', amount: 1500.00, currency: 'USD', expiresInSeconds: 300 })
    log('sub',      'order_456')
    log('amount',   '1500')
    log('currency', 'USD')
    orderToken = r.token
    pass('sign() payment order — custom fields accepted')
  } catch (err) { fail('sign() payment order', err) }

  try {
    const r = await pq.sign({ sub: 'doc_789', hash: 'sha256:abc123', signedBy: 'alice' })
    log('sub',      'doc_789')
    log('hash',     'sha256:abc123')
    log('signedBy', 'alice')
    docToken = r.token
    pass('sign() document — custom fields accepted')
  } catch (err) { fail('sign() document', err) }

  try {
    await pq.sign({ sub: '' })
    fail('sign() rejects empty sub', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'MISSING_SUB') {
      pass('sign() throws PQAuthError(MISSING_SUB) when sub is empty')
    } else {
      fail('sign() rejects empty sub', err)
    }
  }

  try {
    await pq.sign({})
    fail('sign() rejects missing sub', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'MISSING_SUB') {
      pass('sign() throws PQAuthError(MISSING_SUB) when sub is missing')
    } else {
      fail('sign() rejects missing sub', err)
    }
  }

  try {
    await pq.sign({
      sub: 'test_fields',
      f1: 'a', f2: 'b', f3: 'c', f4: 'd', f5: 'e',
      f6: 'f', f7: 'g', f8: 'h', f9: 'i', f10: 'j', f11: 'k',
    })
    fail('sign() rejects >10 custom fields', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'API_ERROR' && err.status === 400) {
      pass('sign() throws API_ERROR(400) when >10 custom fields')
    } else {
      fail('sign() rejects >10 custom fields', err)
    }
  }

  // ─── 04 verify() remote ──────────────────────────────────────────────────────
  section('04 · verify() — remote')

  if (userToken) {
    try {
      const r = await pq.verify(userToken)
      if (!r.valid)            throw new Error('valid is false')
      if (!r.payload?.sub)     throw new Error('missing payload.sub')
      if (r.payload.sub !== 'user_test') throw new Error('sub is "' + r.payload.sub + '", expected "user_test"')
      if (r.payload.role !== 'admin')    throw new Error('role is "' + r.payload.role + '", expected "admin"')
      if (typeof r.payload.iat !== 'number') throw new Error('missing payload.iat')
      if (typeof r.payload.exp !== 'number') throw new Error('missing payload.exp')
      if (r.local !== false)   throw new Error('local should be false for remote verify')
      log('valid', String(r.valid))
      log('sub',   r.payload.sub)
      log('role',  String(r.payload.role))
      log('iat',   String(r.payload.iat))
      log('exp',   String(r.payload.exp))
      log('local', String(r.local))
      pass('verify() valid token — correct payload returned')
    } catch (err) { fail('verify() valid token', err) }

    try {
      const tampered = { ...userToken, payload: 'TAMPERED_PAYLOAD' }
      const r = await pq.verify(tampered)
      if (r.valid)  throw new Error('valid should be false for tampered token')
      if (!r.error) throw new Error('missing error message')
      log('valid', String(r.valid))
      log('error', r.error)
      pass('verify() tampered token — returns valid:false without throwing')
    } catch (err) { fail('verify() tampered token', err) }
  }

  if (orderToken) {
    try {
      const r = await pq.verify(orderToken)
      if (!r.valid) throw new Error('valid is false')
      if (r.payload.sub !== 'order_456') throw new Error('sub is "' + r.payload.sub + '"')
      if (r.payload.amount !== 1500)     throw new Error('amount is ' + r.payload.amount)
      log('sub',    r.payload.sub)
      log('amount', String(r.payload.amount))
      pass('verify() order token — custom fields preserved in payload')
    } catch (err) { fail('verify() order token', err) }
  }

  // ─── 05 verify() local ───────────────────────────────────────────────────────
  section('05 · verify() — local (offline)')

  const pqLocal = new PQAuth({ apiKey: API_KEY, localVerify: true })

  try {
    await pqLocal.preloadPublicKey()
    pass('preloadPublicKey() — fetches and caches public key')
  } catch (err) { fail('preloadPublicKey()', err) }

  if (userToken) {
    try {
      const r = await pqLocal.verify(userToken)
      if (!r.valid)         throw new Error('valid is false')
      if (r.local !== true) throw new Error('local should be true')
      if (r.payload.sub !== 'user_test') throw new Error('sub is "' + r.payload.sub + '"')
      log('valid', String(r.valid))
      log('local', String(r.local))
      log('sub',   r.payload.sub)
      pass('verify() local — valid token verified in-memory without API call')
    } catch (err) { fail('verify() local — valid token', err) }

    try {
      const tampered = { ...userToken, payload: 'TAMPERED' }
      const r = await pqLocal.verify(tampered)
      if (r.valid)          throw new Error('valid should be false')
      if (r.local !== true) throw new Error('local should be true')
      log('valid', String(r.valid))
      log('local', String(r.local))
      pass('verify() local — tampered token rejected in-memory')
    } catch (err) { fail('verify() local — tampered token', err) }
  }

  // ─── 06 revoke() ─────────────────────────────────────────────────────────────
  section('06 · revoke()')
  let revokedToken

  if (docToken) {
    try {
      const r = await pq.revoke(docToken, 'integration test')
      if (!r.success)   throw new Error('success is false')
      if (!r.message)   throw new Error('missing message')
      if (r.sub !== 'doc_789') throw new Error('sub is "' + r.sub + '", expected "doc_789"')
      if (typeof r.revokedAt !== 'number') throw new Error('missing revokedAt')
      if (typeof r.expiresAt !== 'number') throw new Error('missing expiresAt')
      if (!r.note)      throw new Error('missing note')
      log('success',   String(r.success))
      log('message',   r.message)
      log('sub',       r.sub)
      log('revokedAt', String(r.revokedAt))
      log('expiresAt', String(r.expiresAt))
      revokedToken = docToken
      pass('revoke() — token revoked, all fields present')
    } catch (err) { fail('revoke()', err) }
  }

  if (revokedToken) {
    try {
      const r = await pq.verify(revokedToken)
      if (r.valid)  throw new Error('valid should be false for revoked token')
      if (!r.error) throw new Error('missing error message')
      if (r.error !== 'Token has been revoked') throw new Error('unexpected error: ' + r.error)
      log('valid', String(r.valid))
      log('error', r.error)
      pass('verify() revoked token — returns valid:false with correct error')
    } catch (err) { fail('verify() after revoke', err) }

    try {
      const r = await pq.revoke(revokedToken, 'second revoke attempt')
      if (!r.success) throw new Error('success should be true')
      if (!r.message) throw new Error('missing message')
      log('message', r.message)
      pass('revoke() idempotent — revoking already-revoked token returns success')
    } catch (err) { fail('revoke() idempotent', err) }
  }

  try {
    const r = await pq.sign({ sub: 'expire_revoke_test', expiresInSeconds: 1 })
    await sleep(2000)
    await pq.revoke(r.token, 'revoke after expiry')
    fail('revoke() expired token returns 400', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'API_ERROR' && err.status === 400) {
      pass('revoke() expired token — throws API_ERROR(400)')
    } else {
      fail('revoke() expired token returns 400', err)
    }
  }

  // ─── 07 Expired token ────────────────────────────────────────────────────────
  section('07 · Expired token')
  try {
    const r = await pq.sign({ sub: 'expiry_test', expiresInSeconds: 1 })
    pass('sign() with expiresInSeconds:1 — token created')
    console.log('  ' + DIM + 'Waiting 2 seconds for token to expire...' + RESET)
    await sleep(2000)
    const v = await pq.verify(r.token)
    if (v.valid)  throw new Error('valid should be false for expired token')
    if (!v.error) throw new Error('missing error message')
    log('valid', String(v.valid))
    log('error', v.error)
    pass('verify() expired token — returns valid:false')
  } catch (err) { fail('expired token test', err) }

  // ─── 08 usage() ──────────────────────────────────────────────────────────────
  section('08 · usage()')
  try {
    const r = await pq.usage()
    if (!r.current?.month)                            throw new Error('missing current.month')
    if (typeof r.current.freeUsed !== 'number')       throw new Error('missing current.freeUsed')
    if (typeof r.current.freeRemaining !== 'number')  throw new Error('missing current.freeRemaining')
    if (typeof r.current.freeLimit !== 'number')      throw new Error('missing current.freeLimit')
    if (typeof r.current.packRemaining !== 'number')  throw new Error('missing current.packRemaining')
    if (typeof r.current.totalRemaining !== 'number') throw new Error('missing current.totalRemaining')
    if (!Array.isArray(r.monthlyHistory))             throw new Error('monthlyHistory is not an array')
    if (r.monthlyHistory.length !== 6)                throw new Error('monthlyHistory has ' + r.monthlyHistory.length + ' entries, expected 6')
    if (!Array.isArray(r.packs))                      throw new Error('packs is not an array')
    if (!r.developer?.email)                          throw new Error('missing developer.email')
    log('month',          r.current.month)
    log('freeUsed',       String(r.current.freeUsed))
    log('freeRemaining',  String(r.current.freeRemaining))
    log('freeLimit',      String(r.current.freeLimit))
    log('packRemaining',  String(r.current.packRemaining))
    log('totalRemaining', String(r.current.totalRemaining))
    log('historyMonths',  String(r.monthlyHistory.length))
    pass('usage() — correct shape, all fields present, 6-month history')
  } catch (err) { fail('usage()', err) }

  // ─── 09 Local verify — revoked token passes (expected behavior) ──────────────
  section('09 · Local verify — revoked token passes (expected behavior)')
  try {
    const r = await pq.sign({ sub: 'revoke_local_test', expiresInSeconds: 3600 })
    const token = r.token
    await pq.revoke(token, 'test revocation for local verify')

    const remote = await pq.verify(token)
    if (remote.valid) throw new Error('remote verify should reject revoked token')
    pass('revoke() — remote verify rejects revoked token')

    const localResult = await pqLocal.verify(token)
    if (!localResult.valid)         throw new Error('local verify should NOT check revocation — expected valid:true')
    if (localResult.local !== true) throw new Error('local should be true')
    log('valid (local)', String(localResult.valid))
    log('local',         String(localResult.local))
    pass('verify() local — revoked token passes (does not check revocation list — use remote for sensitive ops)')
  } catch (err) { fail('local verify revoked token test', err) }

  // ─── 10 Default expiry ───────────────────────────────────────────────────────
  section('10 · sign() — default expiry (no expiresInSeconds)')
  try {
    const r = await pq.sign({ sub: 'default_expiry_test' })
    const payload = JSON.parse(Buffer.from(r.token.payload, 'base64').toString('utf8'))
    const expectedExp = payload.iat + 3600
    const diff = Math.abs(payload.exp - expectedExp)
    if (diff > 5) throw new Error('exp is ' + payload.exp + ', expected ~' + expectedExp + ' (1 hour from iat)')
    log('iat',          String(payload.iat))
    log('exp',          String(payload.exp))
    log('diff from 1h', String(diff) + 's')
    pass('sign() — default expiresInSeconds is 3600 (1 hour)')
  } catch (err) { fail('sign() default expiry', err) }

  // ─── 11 Malformed tokens ─────────────────────────────────────────────────────
  section('11 · verify() — malformed token shapes')
  try {
    const r = await pq.verify({ payload: '', signature: '', algorithm: 'ML-DSA-65', issuedAt: 0 })
    if (r.valid)  throw new Error('should be invalid')
    if (!r.error) throw new Error('missing error message')
    log('valid', String(r.valid))
    log('error', r.error)
    pass('verify() empty payload/signature — returns valid:false without throwing')
  } catch (err) { fail('verify() empty payload/signature', err) }

  try {
    const r = await pq.verify({ payload: 'abc', signature: 'xyz', algorithm: 'UNKNOWN-ALG', issuedAt: 0 })
    if (r.valid)  throw new Error('should be invalid')
    if (!r.error) throw new Error('missing error message')
    log('valid', String(r.valid))
    log('error', r.error)
    pass('verify() unknown algorithm — returns valid:false without throwing')
  } catch (err) { fail('verify() unknown algorithm', err) }

  try {
    const r = await pq.verify({})
    if (r.valid) throw new Error('should be invalid')
    log('valid', String(r.valid))
    pass('verify() empty object — returns valid:false without throwing')
  } catch (err) { fail('verify() empty object', err) }

  // ─── 12 Webhooks ─────────────────────────────────────────────────────────────
  section('12 · webhooks — get before register, register, get, test, delete')

  try {
    await pq.webhooks.delete().catch(() => {})
    const { webhook } = await pq.webhooks.get()
    if (webhook !== null) throw new Error('webhook should be null before registering')
    log('webhook', 'null')
    pass('webhooks.get() before register — returns null')
  } catch (err) { fail('webhooks.get() before register', err) }

  try {
    const { webhook } = await pq.webhooks.register({
      url:    WEBHOOK_URL,
      events: ['token.signed', 'limit.warning'],
    })
    if (!webhook.url)                   throw new Error('missing webhook.url')
    if (!webhook.secret)                throw new Error('missing webhook.secret')
    if (!Array.isArray(webhook.events)) throw new Error('events is not an array')
    log('url',    webhook.url)
    log('events', webhook.events.join(', '))
    log('secret', webhook.secret.slice(0, 8) + '...')
    pass('webhooks.register() — webhook created with secret')
  } catch (err) { fail('webhooks.register()', err) }

  try {
    const { webhook } = await pq.webhooks.get()
    if (!webhook)                       throw new Error('webhook is null after register')
    if (!webhook.url)                   throw new Error('missing webhook.url')
    if (!Array.isArray(webhook.events)) throw new Error('events is not an array')
    if (webhook.secret)                 throw new Error('secret should not be returned by get()')
    log('url',    webhook.url)
    log('events', webhook.events.join(', '))
    pass('webhooks.get() — returns webhook without secret')
  } catch (err) { fail('webhooks.get()', err) }

  try {
    const r = await pq.webhooks.test()
    if (!r.message) throw new Error('missing message')
    log('message', r.message)
    pass('webhooks.test() — test event dispatched')
  } catch (err) { fail('webhooks.test()', err) }

  try {
    await pq.webhooks.delete()
    const { webhook } = await pq.webhooks.get()
    if (webhook !== null) throw new Error('webhook should be null after delete')
    pass('webhooks.delete() — webhook removed, get() returns null')
  } catch (err) { fail('webhooks.delete()', err) }

  // ─── 13 Independent ML-DSA-65 signature verification ─────────────────────────
  section('13 · Independent ML-DSA-65 signature verification')
  try {
    const pkResp = await fetch('https://api.fipsign.dev/public-key')
    const pkData = await pkResp.json()
    if (!pkData.publicKey) throw new Error('could not fetch public key')

    const { token } = await pq.sign({ sub: 'crypto_verify_test', expiresInSeconds: 3600 })

    const publicKey = fromBase64(pkData.publicKey)
    const signature = fromBase64(token.signature)
    const message   = new TextEncoder().encode(token.payload)

    const isValid = ml_dsa65.verify(signature, message, publicKey)
    if (!isValid) throw new Error('ML-DSA-65 signature is mathematically invalid')

    log('algorithm', pkData.algorithm)
    log('verified',  'via @noble/post-quantum directly (no SDK verify())')
    log('result',    'valid ✓')
    pass('ML-DSA-65 signature verified independently — cryptography is correct')
  } catch (err) { fail('independent ML-DSA-65 verification', err) }

  // ─── 14 Distinct signatures for identical payloads ───────────────────────────
  section('14 · Distinct signatures for identical payloads')
  try {
    const payload = { sub: 'replay_test', role: 'admin', expiresInSeconds: 3600 }
    const r1 = await pq.sign(payload)
    await sleep(1100) // ensure iat differs — backend uses Unix seconds
    const r2 = await pq.sign(payload)

    if (r1.token.signature === r2.token.signature) {
      throw new Error('signatures are identical — possible replay attack vulnerability')
    }
    if (r1.token.payload === r2.token.payload) {
      throw new Error('payloads are identical — iat should differ between calls')
    }

    log('signature1', r1.token.signature.slice(0, 24) + '...')
    log('signature2', r2.token.signature.slice(0, 24) + '...')
    log('distinct',   'yes ✓')
    pass('signing same payload twice produces distinct signatures — no replay vulnerability')
  } catch (err) { fail('distinct signatures test', err) }

  // ─── 15 Webhook delivery confirmation ────────────────────────────────────────
  section('15 · Webhook delivery confirmation')
  try {
    await pq.webhooks.delete().catch(() => {})
    await pq.webhooks.register({ url: WEBHOOK_URL, events: ['token.signed'] })

    const uniqueSub = 'webhook_delivery_test_' + Date.now()
    await pq.sign({ sub: uniqueSub, expiresInSeconds: 300 })

    console.log('  ' + DIM + 'Waiting 3 seconds for webhook delivery...' + RESET)
    await sleep(3000)

    const whResp = await fetch(
      'https://webhook.site/token/' + WEBHOOK_SITE_TOKEN + '/requests?sorting=newest&per_page=5',
      { headers: { 'Accept': 'application/json' } }
    )

    if (!whResp.ok) throw new Error('webhook.site API returned ' + whResp.status)

    const whData   = await whResp.json()
    const requests = whData.data ?? []

    if (requests.length === 0) throw new Error('no requests received at webhook.site')

    const found = requests.find(req => {
      try {
        const body = typeof req.content === 'string' ? JSON.parse(req.content) : req.content
        return body?.event === 'token.signed' && body?.data?.sub === uniqueSub
      } catch { return false }
    })

    if (!found) throw new Error('event for sub "' + uniqueSub + '" not found in recent requests')

    const body = typeof found.content === 'string' ? JSON.parse(found.content) : found.content
    log('event',     body.event)
    log('sub',       body.data.sub)
    log('timestamp', String(body.timestamp))
    log('delivered', 'yes ✓')
    pass('webhook delivered and confirmed — event arrived with correct payload')

    await pq.webhooks.delete()
  } catch (err) { fail('webhook delivery confirmation', err) }

  // ─── 16 Certificate Authority ─────────────────────────────────────────────
  section('16 · Certificate Authority')

  const ROOT_CERT_JSON = process.env.FIPSIGN_ROOT_CERT_JSON
    ? JSON.parse(process.env.FIPSIGN_ROOT_CERT_JSON)
    : null

  // X.509 root cert PEM — set this when testing against an X.509 CA
  const ROOT_CERT_PEM = process.env.FIPSIGN_ROOT_CERT_PEM ?? null

  if (!ROOT_CERT_JSON && !ROOT_CERT_PEM) {
    console.log('  ' + DIM + 'ℹ FIPSIGN_ROOT_CERT_JSON / FIPSIGN_ROOT_CERT_PEM not set — offline verifyCert() tests will be skipped.' + RESET)
    console.log('  ' + DIM + '  PQCert:  FIPSIGN_ROOT_CERT_JSON=\'$(cat root-cert.json)\' node test-sdk.mjs' + RESET)
    console.log('  ' + DIM + '  X.509:   FIPSIGN_ROOT_CERT_PEM=\'$(cat root-cert.pem)\' node test-sdk.mjs' + RESET)
  }

  // 16.1 generateKeyPair
  let devicePublicKey, deviceSecretKey
  try {
    const { generateKeyPair } = await import('fipsign-sdk')
    const kp = await generateKeyPair()
    if (!kp.publicKey)  throw new Error('missing publicKey')
    if (!kp.secretKey)  throw new Error('missing secretKey')
    if (typeof kp.publicKey !== 'string') throw new Error('publicKey must be a string')
    if (typeof kp.secretKey !== 'string') throw new Error('secretKey must be a string')
    const decoded = atob(kp.publicKey)
    if (decoded.length === 0) throw new Error('publicKey decoded to empty bytes')
    log('publicKey length',  String(atob(kp.publicKey).length) + ' bytes')
    log('secretKey length',  String(atob(kp.secretKey).length) + ' bytes')
    devicePublicKey = kp.publicKey
    deviceSecretKey = kp.secretKey
    pass('generateKeyPair() — ML-DSA-65 key pair generated')
  } catch (err) { fail('generateKeyPair()', err) }

  // 16.2 ca.issue()
  // Detect CA format from the certificate field:
  //   PQCert → r.certificate is an object with .type, .id, .signature, etc.
  //   X.509  → r.certificate is a PEM string starting with "-----BEGIN CERTIFICATE-----"
  let issuedCert, issuedCertId
  try {
    if (!devicePublicKey) throw new Error('skipped — generateKeyPair() failed')
    const r = await pq.ca.issue({
      subject:          'device-test-' + Date.now(),
      publicKey:        devicePublicKey,
      expiresInSeconds: 86400,
      meta:             { env: 'test', sdk: 'fipsign-sdk' },
    })
    if (!r.certificate)           throw new Error('missing certificate')
    if (!r.meta.certId)           throw new Error('missing meta.certId')
    if (typeof r.usage.freeRemaining !== 'number') throw new Error('missing usage.freeRemaining')

    const isX509 = typeof r.certificate === 'string'

    if (isX509) {
      // X.509 — certificate is a PEM string, metadata comes from meta
      if (!r.certificate.includes('BEGIN CERTIFICATE')) throw new Error('X.509 certificate is not a valid PEM string')
      if (!r.meta.caId)      throw new Error('missing meta.caId')
      if (!r.meta.expiresAt) throw new Error('missing meta.expiresAt')
      log('format',    'x509')
      log('certId',    r.meta.certId)
      log('caId',      r.meta.caId)
      log('expiresAt', new Date(r.meta.expiresAt * 1000).toISOString())
      log('pem length', String(r.certificate.length) + ' chars')
    } else {
      // PQCert — certificate is a JSON object
      if (r.certificate.type !== 'CA_CERT') throw new Error('expected CA_CERT, got ' + r.certificate.type)
      if (!r.certificate.id)        throw new Error('missing certificate.id')
      if (!r.certificate.signature) throw new Error('missing certificate.signature')
      if (!r.certificate.caId)      throw new Error('missing certificate.caId')
      if (!r.certificate.expiresAt) throw new Error('missing certificate.expiresAt')
      log('format',    'pqcert')
      log('certId',    r.meta.certId)
      log('caId',      r.certificate.caId)
      log('subject',   r.certificate.subject)
      log('expiresAt', new Date(r.certificate.expiresAt * 1000).toISOString())
      log('algorithm', r.certificate.algorithm)
    }

    issuedCert   = r.certificate  // PQCert object or PEM string
    issuedCertId = r.meta.certId
    pass('ca.issue() — certificate issued with correct shape')
  } catch (err) { fail('ca.issue()', err) }

  // 16.3 ca.issue() — expiresInSeconds below minimum (< 60)
  try {
    if (!devicePublicKey) throw new Error('skipped — generateKeyPair() failed')
    await pq.ca.issue({
      subject:          'device-expire-min-test',
      publicKey:        devicePublicKey,
      expiresInSeconds: 30,
    })
    fail('ca.issue() rejects expiresInSeconds < 60', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'API_ERROR' && err.status === 400) {
      log('expiresInSeconds', '30 → rejected')
      pass('ca.issue() — throws API_ERROR(400) when expiresInSeconds < 60')
    } else {
      fail('ca.issue() rejects expiresInSeconds < 60', err)
    }
  }

  // 16.4 ca.issue() — expiresInSeconds above maximum (> 5 years)
  try {
    if (!devicePublicKey) throw new Error('skipped — generateKeyPair() failed')
    await pq.ca.issue({
      subject:          'device-expire-max-test',
      publicKey:        devicePublicKey,
      expiresInSeconds: 200_000_000,
    })
    fail('ca.issue() rejects expiresInSeconds > 5 years', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'API_ERROR' && err.status === 400) {
      log('expiresInSeconds', '200_000_000 → rejected')
      pass('ca.issue() — throws API_ERROR(400) when expiresInSeconds > 5 years')
    } else {
      fail('ca.issue() rejects expiresInSeconds > 5 years', err)
    }
  }

  // 16.5 ca.verifyCert() offline — optional (requires FIPSIGN_ROOT_CERT_JSON)
  if (ROOT_CERT_JSON) {
    try {
      if (!issuedCert) throw new Error('skipped — ca.issue() failed')
      const result = pq.ca.verifyCert(issuedCert, ROOT_CERT_JSON)
      if (!result.valid) throw new Error('verifyCert returned invalid: ' + result.error)
      log('valid',   String(result.valid))
      log('subject', result.cert?.subject)
      pass('ca.verifyCert() offline — certificate signature valid against root cert')
    } catch (err) { fail('ca.verifyCert() offline', err) }

    // 16.5b tampered cert should fail
    try {
      if (!issuedCert) throw new Error('skipped — ca.issue() failed')
      const tampered = { ...issuedCert, subject: 'tampered-subject' }
      const result   = pq.ca.verifyCert(tampered, ROOT_CERT_JSON)
      if (result.valid) throw new Error('should have been invalid — cert was tampered')
      log('valid', String(result.valid))
      log('error', result.error)
      pass('ca.verifyCert() — tampered certificate correctly rejected')
    } catch (err) { fail('ca.verifyCert() tampered cert', err) }

    // 16.5c wrong CA should fail
    try {
      if (!issuedCert) throw new Error('skipped — ca.issue() failed')
      const wrongRoot = { ...ROOT_CERT_JSON, id: 'ca_wrong_id_000' }
      const result    = pq.ca.verifyCert(issuedCert, wrongRoot)
      if (result.valid) throw new Error('should have been invalid — wrong CA')
      log('valid', String(result.valid))
      log('error', result.error)
      pass('ca.verifyCert() — wrong CA root correctly rejected')
    } catch (err) { fail('ca.verifyCert() wrong CA', err) }

    // 16.5d expired cert should fail verifyCert()
    try {
      if (!devicePublicKey) throw new Error('skipped — generateKeyPair() failed')
      // Issue a cert with minimum TTL (60s), wait for it to expire, then verify
      const r = await pq.ca.issue({
        subject:          'device-expire-verify-test',
        publicKey:        devicePublicKey,
        expiresInSeconds: 60,
      })
      const expiredCert = r.certificate
      log('issued cert expiresAt', new Date(expiredCert.expiresAt * 1000).toISOString())
      console.log('  ' + DIM + 'Waiting 62 seconds for certificate to expire...' + RESET)
      await sleep(62_000)
      const result = pq.ca.verifyCert(expiredCert, ROOT_CERT_JSON)
      if (result.valid) throw new Error('expired cert should fail verifyCert()')
      if (!result.error) throw new Error('missing error message')
      log('valid', String(result.valid))
      log('error', result.error)
      pass('ca.verifyCert() — expired certificate correctly rejected with CERT_EXPIRED')
      // Clean up
      await pq.ca.revokeCert(expiredCert.id, 'expired test cert cleanup').catch(() => {})
    } catch (err) { fail('ca.verifyCert() expired cert', err) }
  } else {
    console.log('  ' + DIM + '  → ca.verifyCert() offline tests skipped (no FIPSIGN_ROOT_CERT_JSON)' + RESET)
  }

  // 16.5e ca.verifyX509Cert() offline — optional (requires FIPSIGN_ROOT_CERT_PEM)
  if (ROOT_CERT_PEM) {
    try {
      if (!issuedCert) throw new Error('skipped — ca.issue() failed')
      if (typeof issuedCert !== 'string') throw new Error('skipped — CA is not X.509 format')
      const result = await pq.ca.verifyX509Cert(issuedCert, ROOT_CERT_PEM)
      if (!result.valid) throw new Error('verifyX509Cert returned invalid: ' + result.error)
      log('valid', String(result.valid))
      log('cert',  result.cert?.slice(0, 27) + '...')
      pass('ca.verifyX509Cert() offline — X.509 cert signature valid against root PEM')
    } catch (err) { fail('ca.verifyX509Cert() offline', err) }

    // tampered PEM should fail
    try {
      if (!issuedCert || typeof issuedCert !== 'string') throw new Error('skipped — not X.509')
      // Adulterar bytes en el medio del base64 (lejos de los headers y footer)
      // Extraer las líneas de contenido y modificar una en el medio
      const lines = issuedCert.split('\n')
      const contentLines = lines.filter(l => l && !l.startsWith('-----'))
      const midIdx = Math.floor(contentLines.length / 2)
      // Rotar un carácter para garantizar que el DER cambia
      const origChar = contentLines[midIdx][4]
      const newChar  = origChar === 'A' ? 'B' : 'A'
      const tamperedLine = contentLines[midIdx].slice(0, 4) + newChar + contentLines[midIdx].slice(5)
      const tampered = issuedCert.replace(contentLines[midIdx], tamperedLine)
      const result   = await pq.ca.verifyX509Cert(tampered, ROOT_CERT_PEM)
      if (result.valid) throw new Error('should have been invalid — cert was tampered')
      log('valid', String(result.valid))
      log('error', result.error)
      pass('ca.verifyX509Cert() — tampered X.509 certificate correctly rejected')
    } catch (err) { fail('ca.verifyX509Cert() tampered cert', err) }

    // wrong root PEM should fail
    try {
      if (!issuedCert || typeof issuedCert !== 'string') throw new Error('skipped — not X.509')
      // Use the leaf cert as a fake root — signature won't match
      const result = await pq.ca.verifyX509Cert(issuedCert, issuedCert)
      if (result.valid) throw new Error('should have been invalid — wrong root')
      log('valid', String(result.valid))
      log('error', result.error)
      pass('ca.verifyX509Cert() — wrong root CA correctly rejected')
    } catch (err) { fail('ca.verifyX509Cert() wrong root', err) }
  } else {
    console.log('  ' + DIM + '  → ca.verifyX509Cert() offline tests skipped (no FIPSIGN_ROOT_CERT_PEM)' + RESET)
  }

  // 16.6 ca.getCrl() — before revocation
  // PQCert: { caId, subject, crl: CrlEntry[], generatedAt }
  // X.509:  { crl: { caId, subject, revokedCerts: CrlEntry[], signature, ... }, generatedAt }
  let crlBefore
  try {
    const r = await pq.ca.getCrl()
    if (typeof r.generatedAt !== 'number') throw new Error('missing generatedAt')

    const isX509Crl = r.crl && !Array.isArray(r.crl) && typeof r.crl === 'object'

    let caId, subject, crlEntries
    if (isX509Crl) {
      // X.509 signed CRL — fields are inside r.crl
      caId       = r.crl.caId
      subject    = r.crl.subject
      crlEntries = r.crl.revokedCerts
      if (!r.crl.signature) throw new Error('X.509 CRL missing signature')
    } else {
      // PQCert CRL — fields are at the root
      caId       = r.caId
      subject    = r.subject
      crlEntries = r.crl
    }

    if (!caId)                    throw new Error('missing caId')
    if (!subject)                 throw new Error('missing subject')
    if (!Array.isArray(crlEntries)) throw new Error('crl entries is not an array')

    log('caId',        caId)
    log('subject',     subject)
    log('crl entries', String(crlEntries.length))
    log('format',      isX509Crl ? 'x509 signed CRL' : 'pqcert')
    crlBefore = crlEntries
    pass('ca.getCrl() — CRL returned with correct shape')
  } catch (err) { fail('ca.getCrl()', err) }

  // 16.7 ca.isCertRevoked() — before revocation
  try {
    if (!issuedCertId || !crlBefore) throw new Error('skipped — previous steps failed')
    const revoked = pq.ca.isCertRevoked(issuedCertId, crlBefore)
    if (revoked) throw new Error('cert should NOT be revoked yet')
    log('revoked', String(revoked))
    pass('ca.isCertRevoked() — cert correctly not in CRL before revocation')
  } catch (err) { fail('ca.isCertRevoked() before revocation', err) }

  // 16.8 ca.getCert() — existing cert
  try {
    if (!issuedCertId) throw new Error('skipped — ca.issue() failed')
    const r = await pq.ca.getCert(issuedCertId)
    if (!r.certificate)          throw new Error('missing certificate')
    if (!r.status)               throw new Error('missing status')
    if (r.status.revoked)        throw new Error('cert should not be revoked yet')
    if (r.status.expired)        throw new Error('cert should not be expired')
    if (r.status.revokedAt !== null) throw new Error('revokedAt should be null')
    // For PQCert: certificate is an object with .id
    // For X.509:  certificate is a PEM string — log its length instead
    const certLabel = typeof r.certificate === 'string'
      ? r.certificate.slice(0, 27) + '...'
      : r.certificate.id
    log('certId',  certLabel)
    log('revoked', String(r.status.revoked))
    log('expired', String(r.status.expired))
    pass('ca.getCert() — certificate retrieved with correct status')
  } catch (err) { fail('ca.getCert()', err) }

  // 16.9 ca.getCert() — non-existent certId returns 404
  try {
    await pq.ca.getCert('cert_nonexistent_000000000000000000000000')
    fail('ca.getCert() non-existent certId — should have thrown', new Error('did not throw'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'API_ERROR' && err.status === 404) {
      log('certId', 'cert_nonexistent_... → 404')
      pass('ca.getCert() — throws API_ERROR(404) for non-existent certId')
    } else {
      fail('ca.getCert() non-existent certId', err)
    }
  }

  // 16.10 ca.revokeCert()
  try {
    if (!issuedCertId) throw new Error('skipped — ca.issue() failed')
    const r = await pq.ca.revokeCert(issuedCertId, 'sdk integration test')
    if (!r.certId)               throw new Error('missing certId')
    if (!r.revokedAt)            throw new Error('missing revokedAt')
    if (r.reason !== 'sdk integration test') throw new Error('wrong reason: ' + r.reason)
    if (typeof r.usage.freeRemaining !== 'number') throw new Error('missing usage')
    log('certId',    r.certId)
    log('revokedAt', new Date(r.revokedAt * 1000).toISOString())
    log('reason',    r.reason)
    pass('ca.revokeCert() — certificate revoked successfully')
  } catch (err) { fail('ca.revokeCert()', err) }

  // 16.11 ca.revokeCert() — already revoked should return 409
  try {
    if (!issuedCertId) throw new Error('skipped — ca.issue() failed')
    await pq.ca.revokeCert(issuedCertId, 'duplicate revocation')
    fail('ca.revokeCert() duplicate — should have thrown', new Error('did not throw'))
  } catch (err) {
    if (err instanceof PQAuthError && err.status === 409) {
      pass('ca.revokeCert() duplicate — correctly returns 409')
    } else {
      fail('ca.revokeCert() duplicate', err)
    }
  }

  // 16.12 ca.getCrl() — after revocation
  let crlAfter
  try {
    const r = await pq.ca.getCrl()
    const isX509Crl = r.crl && !Array.isArray(r.crl) && typeof r.crl === 'object'
    const crlEntries = isX509Crl ? r.crl.revokedCerts : r.crl

    crlAfter = crlEntries
    // Verify reason field — may be null if no reason was given
    const entry = crlEntries.find(e => e.certId === issuedCertId)
    if (entry) {
      const reasonIsValid = entry.reason === null || typeof entry.reason === 'string'
      if (!reasonIsValid) throw new Error('reason must be string or null, got: ' + typeof entry.reason)
      log('reason type', entry.reason === null ? 'null' : '"' + entry.reason + '"')
    }
    log('crl entries after revocation', String(crlEntries.length))
    pass('ca.getCrl() after revocation — CRL fetched, reason field is string or null')
  } catch (err) { fail('ca.getCrl() after revocation', err) }

  // 16.13 ca.isCertRevoked() — after revocation
  try {
    if (!issuedCertId || !crlAfter) throw new Error('skipped — previous steps failed')
    // For X.509: issuedCert is a PEM string — pass issuedCertId directly.
    // For PQCert: issuedCert is a PQCert object — isCertRevoked reads .id from it.
    // Using issuedCertId works for both formats.
    const revoked = pq.ca.isCertRevoked(issuedCertId, crlAfter)
    if (!revoked) throw new Error('cert SHOULD be revoked now')
    log('revoked', String(revoked))
    pass('ca.isCertRevoked() — cert correctly found in CRL after revocation')
  } catch (err) { fail('ca.isCertRevoked() after revocation', err) }

  // 16.14 ca.getCert() — status after revocation
  try {
    if (!issuedCertId) throw new Error('skipped — ca.issue() failed')
    const r = await pq.ca.getCert(issuedCertId)
    if (!r.status.revoked)    throw new Error('cert should be revoked now')
    if (!r.status.revokedAt)  throw new Error('revokedAt should be set')
    log('revoked',   String(r.status.revoked))
    log('revokedAt', new Date(r.status.revokedAt * 1000).toISOString())
    pass('ca.getCert() after revocation — status.revoked is true')
  } catch (err) { fail('ca.getCert() after revocation', err) }

  // ─── Summary ──────────────────────────────────────────────────────────────────
  const total = passed + failed
  console.log('\n' + '─'.repeat(48))
  console.log(BOLD + 'Results: ' + passed + '/' + total + ' passed' + RESET)
  if (failed === 0) {
    console.log(GREEN + BOLD + 'All tests passed. SDK is working correctly.' + RESET + '\n')
  } else {
    console.log(RED + BOLD + failed + ' test(s) failed. See above for details.' + RESET + '\n')
    process.exit(1)
  }
}

run().catch(err => {
  console.error('\n' + RED + 'Unexpected error:' + RESET, err)
  process.exit(1)
})
