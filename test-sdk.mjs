/**
 * PQSign SDK — Integration test
 * Runs against the live backend using the published pqauth-sdk@0.4.3
 *
 * Usage: node test-sdk.mjs
 */

import { PQAuth, PQAuthError } from 'pqauth-sdk'

const API_KEY = 'pqa_b7fa9e9da3761fe417b78d894a1910363a91ad453f6567b7d31ef70ed4270a64'

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

async function run() {
  console.log('\n' + BOLD + 'PQSign SDK — Integration Test' + RESET)
  console.log(DIM + 'pqauth-sdk@0.4.3 · ' + new Date().toISOString() + RESET + '\n')

  const pq = new PQAuth(API_KEY)

  // 01 Health
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

  // 02 Invalid API key
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

  // 03 Sign
  section('03 · sign()')
  let userToken, orderToken, docToken

  try {
    const r = await pq.sign({ sub: 'user_test', email: 'test@pqsign.io', role: 'admin', expiresInSeconds: 3600 })
    if (!r.token?.payload)   throw new Error('missing token.payload')
    if (!r.token?.signature) throw new Error('missing token.signature')
    if (r.token.algorithm !== 'ML-DSA-65') throw new Error('wrong algorithm: ' + r.token.algorithm)
    if (r.meta.tokenCost !== 1) throw new Error('tokenCost is ' + r.meta.tokenCost + ', expected 1')
    if (!['free','pack','free+pack'].includes(r.meta.source)) throw new Error('unexpected source: ' + r.meta.source)
    if (typeof r.usage.freeRemaining !== 'number') throw new Error('missing usage.freeRemaining')
    log('sub',           'user_test')
    log('algorithm',     r.token.algorithm)
    log('tokenCost',     String(r.meta.tokenCost))
    log('source',        r.meta.source)
    log('freeRemaining', String(r.usage.freeRemaining))
    userToken = r.token
    pass('sign() user session — correct shape and fields')
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
    fail('sign() rejects missing sub', new Error('should have thrown'))
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'MISSING_SUB') {
      pass('sign() throws PQAuthError(MISSING_SUB) when sub is empty')
    } else {
      fail('sign() rejects missing sub', err)
    }
  }

  // 04 Verify remote
  section('04 · verify() — remote')

  if (userToken) {
    try {
      const r = await pq.verify(userToken)
      if (!r.valid)            throw new Error('valid is false')
      if (!r.payload?.sub)     throw new Error('missing payload.sub')
      if (r.payload.sub !== 'user_test') throw new Error('sub is "' + r.payload.sub + '", expected "user_test"')
      if (r.payload.role !== 'admin')    throw new Error('role is "' + r.payload.role + '", expected "admin"')
      if (r.local !== false)   throw new Error('local should be false for remote verify')
      log('valid', String(r.valid))
      log('sub',   r.payload.sub)
      log('role',  String(r.payload.role))
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

  // 05 Local verify
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

  // 06 Revoke
  section('06 · revoke()')
  let revokedToken

  if (docToken) {
    try {
      const r = await pq.revoke(docToken, 'integration test')
      if (!r.success) throw new Error('success is false')
      if (!r.message) throw new Error('missing message')
      if (r.sub !== 'doc_789') throw new Error('sub is "' + r.sub + '", expected "doc_789"')
      log('success', String(r.success))
      log('message', r.message)
      log('sub',     r.sub)
      revokedToken = docToken
      pass('revoke() — token revoked successfully')
    } catch (err) { fail('revoke()', err) }
  }

  if (revokedToken) {
    try {
      const r = await pq.verify(revokedToken)
      if (r.valid)  throw new Error('valid should be false for revoked token')
      if (!r.error) throw new Error('missing error message')
      log('valid', String(r.valid))
      log('error', r.error)
      pass('verify() revoked token — returns valid:false')
    } catch (err) { fail('verify() after revoke', err) }
  }

  // 07 Expired token
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

  // 08 Usage
  section('08 · usage()')
  try {
    const r = await pq.usage()
    if (!r.current?.month)                           throw new Error('missing current.month')
    if (typeof r.current.freeRemaining !== 'number') throw new Error('missing freeRemaining')
    if (typeof r.current.freeLimit !== 'number')     throw new Error('missing freeLimit')
    if (!Array.isArray(r.monthlyHistory))            throw new Error('monthlyHistory is not an array')
    if (r.monthlyHistory.length !== 6)               throw new Error('monthlyHistory has ' + r.monthlyHistory.length + ' entries, expected 6')
    if (!Array.isArray(r.packs))                     throw new Error('packs is not an array')
    log('month',         r.current.month)
    log('freeRemaining', String(r.current.freeRemaining))
    log('freeLimit',     String(r.current.freeLimit))
    log('packRemaining', String(r.current.packRemaining))
    log('historyMonths', String(r.monthlyHistory.length))
    pass('usage() — correct shape, 6-month history present')
  } catch (err) { fail('usage()', err) }

  // Summary
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
