#!/usr/bin/env node
/**
 * mandate.verify() - what it returns when FIPSign denies a call and when the answer never arrives.
 *
 * Offline: no API key, no network, no tokens. A stub FIPSign on localhost sends exactly the replies we need.
 *
 * Usage:  npm run build && node test-mandate-failure.mjs
 * (it imports 'fipsign-sdk', which inside this repo is the build in dist/)
 *
 * What it checks, for 25 kinds of answer (and a few more things at the end):
 *   - a call that is not granted is always result 'denied' (never a third value) and always has a `failure`;
 *   - 'outcome_unknown' (the call may have been granted and charged) only when no usable answer arrived;
 *   - the SDK sends exactly one request per call: it never repeats a call by itself.
 */
import { createServer } from 'node:http'
import { PQAuth } from 'fipsign-sdk'

const GREEN = '\x1b[32m', RED = '\x1b[31m', BOLD = '\x1b[1m', RESET = '\x1b[0m'
let passed = 0, failed = 0
const pass = name => { passed++; console.log(GREEN + 'PASS' + RESET + '  ' + name) }
const fail = (name, why) => { failed++; console.log(RED + 'FAIL' + RESET + '  ' + name + '\n        ' + why) }

// ─── The stub FIPSign ────────────────────────────────────────────────────────

let hits = 0
let lastBody = ''
let behavior = () => {}
const stub = createServer((req, res) => {
  hits++
  const chunks = []
  req.on('data', c => chunks.push(c))
  req.on('end', () => { lastBody = Buffer.concat(chunks).toString('utf8'); behavior(req, res) })
})
await new Promise(resolve => stub.listen(0, resolve))
const baseUrl = 'http://localhost:' + stub.address().port

const json  = (status, body, headers = {}) => (req, res) => {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers })
  res.end(JSON.stringify(body))
}
const text  = (status, body, type = 'text/html') => (req, res) => {
  res.writeHead(status, { 'Content-Type': type })
  res.end(body)
}
const never = () => {}                                              // the request is received and never answered
const drop  = (req) => { req.socket.destroy() }                     // the connection breaks before any answer
const cut   = (status, headers = {}) => (req, res) => {             // the answer starts, then the connection breaks
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': '200', ...headers })
  res.write('{"result":"gra')
  setTimeout(() => req.socket.destroy(), 20)
}
const stall = (status) => (req, res) => {                           // the answer starts and never ends
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': '200' })
  res.write('{"result":"gra')
}

const KEY   = 'pqa_' + 'a'.repeat(64)
const pq    = new PQAuth({ apiKey: KEY, baseUrl, timeout: 400 })
const TOKEN = { payload: 'eyJ4IjoxfQ==', signature: 'AAAA', algorithm: 'ML-DSA-65', issuedAt: 1 }

const RATE  = { success: false, error: 'Rate limit exceeded. Maximum 300 requests per minute per API key.', code: 'rate_limited' }
const QUOTA = { success: false, error: 'Token limit reached.', code: 'token_quota_exhausted' }
const FAILURES = ['rejected', 'rate_limited', 'quota_exhausted', 'unavailable', 'outcome_unknown']

// [label, what the stub does, expected result, expected failure, expected retryAfter, what `reason` must be (text) or start with (RegExp)]
const CASES = [
  ['200 granted',                                       json(200, { success: true, result: 'granted', actionMatched: 'send_email', budgetRemaining: 4, expiresInSeconds: 60 }), 'granted', undefined, undefined, undefined],
  ['403 denied: scope_not_authorized (+ authorizedScope)', json(403, { success: false, result: 'denied', reason: 'scope_not_authorized', authorizedScope: ['read'] }),  'denied', 'rejected', undefined, 'scope_not_authorized'],
  ['403 denied: budget_exhausted (+ units)',            json(403, { success: false, result: 'denied', reason: 'budget_exhausted', budgetConsumedUnits: 5, budgetTotalUnits: 5 }), 'denied', 'rejected', undefined, 'budget_exhausted'],
  ['403 denied: agent_signature_replayed',              json(403, { success: false, result: 'denied', reason: 'agent_signature_replayed' }),                             'denied', 'rejected', undefined, 'agent_signature_replayed'],
  ['400 request not well formed',                       json(400, { success: false, error: '"cost" must be a non-negative integer' }),                                    'denied', 'rejected', undefined, '"cost" must be a non-negative integer'],
  ['401 invalid API key',                               json(401, { success: false, error: 'API key required or invalid. Include the X-API-Key header.' }),               'denied', 'unavailable', undefined, 'API key required or invalid. Include the X-API-Key header.'],
  ['415 unsupported content type',                      json(415, { success: false, error: 'Content-Type must be application/json' }),                                     'denied', 'unavailable', undefined, 'Content-Type must be application/json'],
  ['429 rate limit + Retry-After 7',                    json(429, RATE, { 'Retry-After': '7' }),                                                                           'denied', 'rate_limited', 7, RATE.error],
  ['429 rate limit without Retry-After',                json(429, RATE),                                                                                                   'denied', 'rate_limited', undefined, RATE.error],
  ['429 token quota exhausted',                         json(429, QUOTA),                                                                                                  'denied', 'quota_exhausted', undefined, QUOTA.error],
  ['429 from a gateway (HTML)',                         text(429, '<html>Too Many Requests</html>'),                                                                       'denied', 'rate_limited', undefined, 'Request failed with status 429'],
  ['403 from a firewall (HTML)',                        text(403, '<html>Forbidden</html>'),                                                                               'denied', 'unavailable', undefined, 'Request failed with status 403'],
  ['500 server error (JSON)',                           json(500, { success: false, error: 'Internal server error' }),                                                     'denied', 'outcome_unknown', undefined, 'Internal server error'],
  ['502 bad gateway (HTML)',                            text(502, '<html>Bad Gateway</html>'),                                                                             'denied', 'outcome_unknown', undefined, 'Request failed with status 502'],
  ['503 empty body',                                    text(503, '', 'text/plain'),                                                                                       'denied', 'outcome_unknown', undefined, 'Request failed with status 503'],
  ['200 but the body is HTML',                          text(200, '<html>hello</html>'),                                                                                   'denied', 'outcome_unknown', undefined, 'Request failed with status 200'],
  ['200 JSON without "result"',                         json(200, { success: true }),                                                                                      'denied', 'outcome_unknown', undefined, 'Request failed with status 200'],
  ['200 with body null',                                text(200, 'null', 'application/json'),                                                                             'denied', 'outcome_unknown', undefined, 'Request failed with status 200'],
  ['connection dropped before any answer',              drop,                                                                                                              'denied', 'outcome_unknown', undefined, /^Network error/],
  ['no answer within the timeout',                      never,                                                                                                             'denied', 'outcome_unknown', undefined, 'Request timed out'],
  ['200 starts and never ends (timeout)',               stall(200),                                                                                                        'denied', 'outcome_unknown', undefined, 'Request timed out'],
  ['200 starts, then the connection breaks',            cut(200),                                                                                                          'denied', 'outcome_unknown', undefined, /^Network error/],
  ['429 starts, then the connection breaks (+ Retry-After 5)', cut(429, { 'Retry-After': '5' }),                                                                           'denied', 'rate_limited', 5, /^Network error/],
  ['403 starts, then the connection breaks',            cut(403),                                                                                                          'denied', 'unavailable', undefined, /^Network error/],
]

for (const [label, doStub, result, failure, retryAfter, reason] of CASES) {
  hits = 0
  behavior = doStub
  const r = await pq.mandate.verify(TOKEN, 'send_email', 1)
  const problems = []
  if (r.result !== result) problems.push('result is ' + JSON.stringify(r.result) + ', expected ' + result)
  if (r.failure !== failure) problems.push('failure is ' + JSON.stringify(r.failure) + ', expected ' + JSON.stringify(failure))
  if (r.retryAfter !== retryAfter) problems.push('retryAfter is ' + JSON.stringify(r.retryAfter) + ', expected ' + JSON.stringify(retryAfter))
  if (reason instanceof RegExp ? !reason.test(String(r.reason)) : (reason !== undefined && r.reason !== reason)) {
    problems.push('reason is ' + JSON.stringify(r.reason) + ', expected ' + String(reason))
  }
  if (result === 'denied' && !FAILURES.includes(r.failure)) problems.push('a denied call without a known failure')
  if (hits !== 1) problems.push('the stub got ' + hits + ' requests, expected exactly 1 (no repeats)')
  problems.length ? fail(label, problems.join('; ')) : pass(label + (failure ? '  ->  ' + failure : ''))
}

// ─── The rest ────────────────────────────────────────────────────────────────

// What a denial from FIPSign carries is passed through untouched.
{
  hits = 0
  behavior = json(403, { success: false, result: 'denied', reason: 'scope_not_authorized', authorizedScope: ['read', 'write'] })
  const r = await pq.mandate.verify(TOKEN, 'delete', 1)
  r.authorizedScope?.join() === 'read,write' ? pass('a denial keeps its authorizedScope') : fail('a denial keeps its authorizedScope', JSON.stringify(r))
  behavior = json(403, { success: false, result: 'denied', reason: 'budget_exhausted', budgetConsumedUnits: 5, budgetTotalUnits: 5 })
  const b = await pq.mandate.verify(TOKEN, 'send_email', 1)
  b.budgetConsumedUnits === 5 && b.budgetTotalUnits === 5 ? pass('a denial keeps budgetConsumedUnits and budgetTotalUnits') : fail('a denial keeps its budget units', JSON.stringify(b))
  behavior = json(200, { success: true, result: 'granted', actionMatched: 'send_email', budgetRemaining: 4, expiresInSeconds: 60, usage: { totalRemaining: 9 } })
  const g = await pq.mandate.verify(TOKEN, 'send_email', 1)
  g.budgetRemaining === 4 && g.expiresInSeconds === 60 && g.usage?.totalRemaining === 9 && !('failure' in g)
    ? pass('a granted call keeps its fields and has no failure') : fail('a granted call', JSON.stringify(g))
}

// What the SDK sends.
{
  behavior = json(200, { success: true, result: 'granted' })
  await pq.mandate.verify(TOKEN, 'send_email', 3)
  const plain = JSON.parse(lastBody)
  const sig = { payload: 'eyJzIjoxfQ==', signature: 'BBBB', algorithm: 'ML-DSA-65', issuedAt: 2 }
  await pq.mandate.verify(TOKEN, 'send_email', 3, { agentSignature: sig })
  const signed = JSON.parse(lastBody)
  plain.action === 'send_email' && plain.cost === 3 && plain.token.signature === 'AAAA' && !('agentSignature' in plain) &&
    signed.agentSignature?.signature === 'BBBB'
    ? pass('the request carries token, action, cost and (only when given) agentSignature')
    : fail('the request body', lastBody)
}

// Nothing listens: a refused connection is also "no answer" (the SDK cannot tell it from a lost one).
{
  const probe = createServer()
  await new Promise(resolve => probe.listen(0, resolve))
  const closedUrl = 'http://localhost:' + probe.address().port
  await new Promise(resolve => probe.close(resolve))
  const r = await new PQAuth({ apiKey: KEY, baseUrl: closedUrl, timeout: 400 }).mandate.verify(TOKEN, 'send_email', 1)
  r.result === 'denied' && r.failure === 'outcome_unknown' && /^Network error/.test(String(r.reason))
    ? pass('connection refused  ->  outcome_unknown') : fail('connection refused', JSON.stringify(r))
}

stub.closeAllConnections?.()
stub.close()
const total = passed + failed
console.log('\n' + '-'.repeat(48))
console.log(BOLD + 'Results: ' + passed + '/' + total + ' passed' + RESET)
process.exit(failed === 0 ? 0 : 1)
