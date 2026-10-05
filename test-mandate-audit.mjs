#!/usr/bin/env node
/**
 * Mandate audit - receipts, the event log, the export, and checking them offline.
 *
 * Offline: no API key, no network, no tokens. A stub FIPSign on localhost answers the calls and records what the SDK sent.
 *
 * Usage:  npm run build && node test-mandate-audit.mjs
 * (it imports 'fipsign-sdk', which inside this repo is the build in dist/)
 *
 * What it checks:
 *   - what the SDK sends: `correlationId` and `receipt` only when asked (every call without them sends what it always sent),
 *     the URLs and query strings of the read calls, pagination, and that a loop that does not advance stops with an error;
 *   - real receipts and a real export captured from FIPSign (test-mandate-audit-fixtures.json), before and after a key rotation:
 *     valid with the right key, invalid with the wrong one, and invalid for every way of altering them;
 *   - logs made here with a fresh project key (ML-DSA-44, -65 and -87): checkpoints, signed head, several pages, non-ASCII text,
 *     a history rewritten with a recomputed chain, events missing at the start, in the middle and at the end;
 *   - the key rules: a list of keys that comes from FIPSign is only trusted through a pinned fingerprint;
 *   - verifyMandateReceipt() and verifyMandateExport() never throw, whatever they are given.
 */
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { PQAuth, PQAuthError, verifyMandateReceipt, verifyMandateExport, publicKeyFingerprint } from 'fipsign-sdk'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

const GREEN = '\x1b[32m', RED = '\x1b[31m', BOLD = '\x1b[1m', RESET = '\x1b[0m'
let passed = 0, failed = 0
const pass = name => { passed++; console.log(GREEN + 'PASS' + RESET + '  ' + name) }
const fail = (name, why) => { failed++; console.log(RED + 'FAIL' + RESET + '  ' + name + '\n        ' + why) }
const check = (name, cond, why = '') => (cond ? pass(name) : fail(name, String(why).slice(0, 700)))
const section = title => console.log('\n' + BOLD + title + RESET)

const FX    = JSON.parse(readFileSync(new URL('./test-mandate-audit-fixtures.json', import.meta.url), 'utf8'))
const clone = x => JSON.parse(JSON.stringify(x))
const b64   = u8 => Buffer.from(u8).toString('base64')
const sha   = x => createHash('sha256').update(x).digest('hex')
const ZERO  = '0'.repeat(64)
const KEY_A = FX.keys.A, KEY_B = FX.keys.B

// A serializer written for this test, apart from the SDK's: keys sorted at every level, arrays keep their order.
const ser = v => Array.isArray(v) ? '[' + v.map(ser).join(',') + ']'
  : (v !== null && typeof v === 'object') ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}'
  : JSON.stringify(v)

// ─── A stub FIPSign: records every request, answers from a queue ─────────────

const seen = []
let queue = []
const stub = createServer((req, res) => {
  let raw = ''
  req.on('data', c => { raw += c })
  req.on('end', () => {
    seen.push({ method: req.method, url: req.url, apiKey: req.headers['x-api-key'], raw, body: raw === '' ? undefined : JSON.parse(raw) })
    const a = queue.length > 0 ? queue.shift() : { http: 200, body: { success: true } }
    res.statusCode = a.http
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify(a.body))
  })
})
await new Promise(r => stub.listen(0, '127.0.0.1', r))
const API_KEY = 'pqa_' + 'ab'.repeat(32)
const pq = new PQAuth({ apiKey: API_KEY, baseUrl: `http://127.0.0.1:${stub.address().port}` })
// Runs `fn` with the stub answering `answers` in order; returns what it gave and every request the stub saw.
async function stubbed(answers, fn) {
  seen.length = 0
  queue = answers.map(a => ('http' in a ? a : { http: 200, body: a }))
  try { return { out: await fn(), requests: [...seen] } } catch (err) { return { err, requests: [...seen] } }
}
const query = url => Object.fromEntries(new URL(url, 'http://x').searchParams)
const path  = url => new URL(url, 'http://x').pathname

const RECEIPT_STUB = FX.receipts.emitted

// ─── 1. What the SDK sends ───────────────────────────────────────────────────

section('1. What the SDK sends')
const EMIT = { agentId: 'bot', issuedBy: 'ops', scope: ['a'], budgetTotal: 1, expiresInSeconds: 60 }
let r = await stubbed([{ success: true, mandate: { id: 'mdt_1' }, receipt: RECEIPT_STUB }], () => pq.mandate.emit({ ...EMIT, correlationId: 'ticket-1' }))
check('emit sends correlationId inside the body of POST /mandate, with the API key', r.requests[0].method === 'POST' && r.requests[0].url === '/mandate' && r.requests[0].body.correlationId === 'ticket-1' && r.requests[0].apiKey === API_KEY, JSON.stringify(r.requests))
check('emit returns the receipt of the answer', r.out.receipt?.event.seq === RECEIPT_STUB.event.seq)
r = await stubbed([{ success: true, mandate: { id: 'mdt_1' } }], () => pq.mandate.emit(EMIT))
check('emit without correlationId: the body is exactly what it was', r.requests[0].raw === JSON.stringify(EMIT), r.requests[0].raw)

const TOKEN = { payload: 'p', signature: 's', algorithm: 'ML-DSA-65', issuedAt: 1 }
const verifyBody = async opts => (await stubbed([{ result: 'granted' }], () => pq.mandate.verify(TOKEN, 'act', 2, opts))).requests[0]
let q = await verifyBody()
check('verify with no options: the body is {token, action, cost}, nothing else', q.url === '/mandate/verify' && q.raw === JSON.stringify({ token: TOKEN, action: 'act', cost: 2 }), q.raw)
q = await verifyBody({ agentSignature: TOKEN })
check('verify with agentSignature: as before', Object.keys(q.body).join() === 'token,action,cost,agentSignature', q.raw)
q = await verifyBody({ receipt: true })
check('verify with receipt: true sends "receipt": true', q.body.receipt === true && Object.keys(q.body).join() === 'token,action,cost,receipt', q.raw)
q = await verifyBody({ receipt: false })
check('verify with receipt: false sends nothing about it', !('receipt' in q.body), q.raw)
q = await verifyBody({ correlationId: 'req-9', receipt: true, agentSignature: TOKEN })
check('verify with everything: all three fields, correlationId as given', q.body.correlationId === 'req-9' && q.body.receipt === true && q.body.agentSignature.signature === 's', q.raw)
r = await stubbed([{ http: 403, body: { result: 'denied', reason: 'scope_not_authorized', receipt: RECEIPT_STUB } }], () => pq.mandate.verify(TOKEN, 'act', 1, { receipt: true }))
check('a denied verify keeps the receipt of the answer, and failure is rejected', r.out.result === 'denied' && r.out.failure === 'rejected' && r.out.receipt?.event.hash === RECEIPT_STUB.event.hash, JSON.stringify(r.out))

const patchBody = async (fn) => (await stubbed([{ success: true, id: 'mdt_1', status: 'active' }], fn)).requests[0]
q = await patchBody(() => pq.mandate.suspend('mdt_1'))
check('suspend with no options: PATCH body is exactly {action}', q.method === 'PATCH' && q.url === '/mandate/mdt_1' && q.raw === '{"action":"suspend"}', q.raw)
q = await patchBody(() => pq.mandate.resume('mdt_1'))
check('resume with no options: {action}', q.raw === '{"action":"resume"}', q.raw)
q = await patchBody(() => pq.mandate.revoke('mdt_1'))
check('revoke with no options: {action}', q.raw === '{"action":"revoke"}', q.raw)
q = await patchBody(() => pq.mandate.narrow('mdt_1', ['a', 'b']))
check('narrow with no options: {action, scope}', q.raw === '{"action":"narrow","scope":["a","b"]}', q.raw)
for (const [name, call, action] of [['suspend', o => pq.mandate.suspend('mdt_1', o), 'suspend'], ['resume', o => pq.mandate.resume('mdt_1', o), 'resume'], ['revoke', o => pq.mandate.revoke('mdt_1', o), 'revoke']]) {
  q = await patchBody(() => call({ correlationId: 'ticket-2' }))
  check(`${name} with correlationId: it goes in the body next to the action`, q.body.action === action && q.body.correlationId === 'ticket-2' && Object.keys(q.body).length === 2, q.raw)
}
q = await patchBody(() => pq.mandate.narrow('mdt_1', ['a'], { correlationId: 'ticket-3' }))
check('narrow with correlationId: action, scope and correlationId', q.body.action === 'narrow' && q.body.scope[0] === 'a' && q.body.correlationId === 'ticket-3', q.raw)
q = await patchBody(() => pq.mandate.suspend('mdt_1', {}))
check('suspend with empty options: nothing extra', q.raw === '{"action":"suspend"}', q.raw)
q = await patchBody(() => pq.mandate.suspend('a/b c'))
check('the id is URL-encoded in the path', q.url === '/mandate/a%2Fb%20c', q.url)
r = await stubbed([{ success: true, id: 'mdt_1', status: 'suspended', receipt: RECEIPT_STUB }], () => pq.mandate.suspend('mdt_1'))
check('a PATCH returns the receipt of the answer', r.out.receipt?.event.hash === RECEIPT_STUB.event.hash)

section('1b. The read calls')
const EV = n => ({ seq: n, type: 'emitted', at: 1, prevHash: ZERO, hash: ZERO, body: '{}' })
r = await stubbed([{ success: true, mandateId: 'm', events: [EV(1)], count: 1, nextAfter: null, head: null }], () => pq.mandate.events('m'))
check('events: GET /mandate/:id/events, no query string without options', r.requests[0].method === 'GET' && r.requests[0].url === '/mandate/m/events' && r.requests[0].apiKey === API_KEY, r.requests[0].url)
r = await stubbed([{ success: true, events: [], count: 0, nextAfter: null, head: null }], () => pq.mandate.events('m', { after: 0, limit: 50 }))
check('events with options: after and limit (after 0 is sent too)', JSON.stringify(query(r.requests[0].url)) === '{"after":"0","limit":"50"}', r.requests[0].url)
r = await stubbed([
  { success: true, events: [EV(1), EV(2)], count: 2, nextAfter: 2, head: null },
  { success: true, events: [EV(3), EV(4)], count: 2, nextAfter: 4, head: null },
  { success: true, events: [EV(5)], count: 1, nextAfter: null, head: null },
], async () => { const s = []; for await (const e of pq.mandate.eventsAll('m', { limit: 2 })) s.push(e.seq); return s })
check('eventsAll follows nextAfter: 3 requests, events 1..5 in order', r.out.join() === '1,2,3,4,5' && r.requests.map(x => x.url).join(' ') === '/mandate/m/events?after=0&limit=2 /mandate/m/events?after=2&limit=2 /mandate/m/events?after=4&limit=2', JSON.stringify(r.requests.map(x => x.url)))
r = await stubbed([
  { success: true, events: [EV(1), EV(2)], count: 2, nextAfter: 2, head: null },
  { success: true, events: [EV(3)], count: 1, nextAfter: null, head: null },
], async () => { for await (const e of pq.mandate.eventsAll('m')) { if (e.seq === 2) break } return 'stopped' })
check('eventsAll: breaking out of the loop asks for no further page', r.out === 'stopped' && r.requests.length === 1, JSON.stringify(r.requests.map(x => x.url)))
r = await stubbed([{ success: true, events: [EV(1)], count: 1, nextAfter: 0, head: null }], async () => { for await (const e of pq.mandate.eventsAll('m')) void e })
check('eventsAll: a nextAfter that does not advance stops with an error instead of looping', r.err instanceof PQAuthError && /did not advance/.test(r.err.message) && r.requests.length === 1, String(r.err))
r = await stubbed([{ http: 404, body: { success: false, error: 'Mandate not found' } }], () => pq.mandate.events('nope'))
check('an error answer becomes a PQAuthError with status and message', r.err instanceof PQAuthError && r.err.status === 404 && r.err.message === 'Mandate not found', String(r.err))

r = await stubbed([{ success: true, events: [], count: 0, nextCursor: null, from: 1, to: 2 }], () => pq.mandate.queryEvents())
check('queryEvents with no query: GET /mandate/events', r.requests[0].url === '/mandate/events', r.requests[0].url)
const FULL_QUERY = { mandateId: 'mdt_1', type: 'verify_denied', action: 'wire:transfer', keyId: 'abcdef0123456789', correlationId: 'a b&c=d/é', traceId: '4bf92f3577b34da6a3ce929d0e0e4736', from: 100, to: 200, limit: 25, cursor: 'xyz_-' }
r = await stubbed([{ success: true, events: [], count: 0, nextCursor: null, from: 1, to: 2 }], () => pq.mandate.queryEvents(FULL_QUERY))
check('queryEvents: every filter goes into the query string, encoded, nothing else', path(r.requests[0].url) === '/mandate/events' && JSON.stringify(query(r.requests[0].url)) === JSON.stringify(Object.fromEntries(Object.entries(FULL_QUERY).map(([k, v]) => [k, String(v)]))), r.requests[0].url)
r = await stubbed([{ success: true, events: [], count: 0, nextCursor: null, from: 1, to: 2 }], () => pq.mandate.queryEvents({ type: 'revoked', action: undefined, from: undefined }))
check('queryEvents: a filter that is undefined is left out', r.requests[0].url === '/mandate/events?type=revoked', r.requests[0].url)
const PE = (n, m = 'mdt_1') => ({ ...EV(n), mandateId: m })
r = await stubbed([
  { success: true, events: [PE(9), PE(8)], count: 2, nextCursor: 'c1', from: 1, to: 2 },
  { success: true, events: [PE(7)], count: 1, nextCursor: 'c2', from: 1, to: 2 },
  { success: true, events: [], count: 0, nextCursor: null, from: 1, to: 2 },
], async () => { const s = []; for await (const e of pq.mandate.queryEventsAll({ type: 'verify_denied', limit: 2 })) s.push(e.seq); return s })
check('queryEventsAll follows nextCursor (an empty page is not the end), keeping the filters', r.out.join() === '9,8,7' && r.requests.length === 3 && !('cursor' in query(r.requests[0].url)) && query(r.requests[1].url).cursor === 'c1' && query(r.requests[2].url).cursor === 'c2' && r.requests.every(x => query(x.url).type === 'verify_denied' && query(x.url).limit === '2'), JSON.stringify(r.requests.map(x => x.url)))
r = await stubbed([{ success: true, events: [PE(1)], count: 1, nextCursor: null, from: 1, to: 2 }], async () => { for await (const e of pq.mandate.queryEventsAll({ cursor: 'c0' })) void e })
check('queryEventsAll starts from the cursor it is given', query(r.requests[0].url).cursor === 'c0', r.requests[0].url)
r = await stubbed([
  { success: true, events: [PE(1)], count: 1, nextCursor: 'same', from: 1, to: 2 },
  { success: true, events: [PE(0)], count: 1, nextCursor: 'same', from: 1, to: 2 },
], async () => { for await (const e of pq.mandate.queryEventsAll()) void e })
check('queryEventsAll: a cursor that does not advance stops with an error', r.err instanceof PQAuthError && /did not advance/.test(r.err.message), String(r.err))

const PAGE = (events, nextAfter) => ({ success: true, format: 'fipsign.mandate.export.v1', projectId: 'p', mandateId: 'm', generatedAt: 1, events, count: events.length, nextAfter, head: null, publicKeys: [] })
r = await stubbed([PAGE([EV(1)], null)], () => pq.mandate.export('m'))
check('export: GET /mandate/:id/export', r.requests[0].method === 'GET' && r.requests[0].url === '/mandate/m/export', r.requests[0].url)
r = await stubbed([PAGE([EV(1)], null)], () => pq.mandate.export('m', { after: 10, limit: 1000 }))
check('export with options: after and limit', JSON.stringify(query(r.requests[0].url)) === '{"after":"10","limit":"1000"}', r.requests[0].url)
r = await stubbed([PAGE([EV(1), EV(2)], 2), PAGE([EV(3), EV(4)], 4), PAGE([EV(5)], null)], () => pq.mandate.exportAll('m', { limit: 2 }))
check('exportAll: every page, in order, following nextAfter', r.out.length === 3 && r.out.map(p => p.events.length).join() === '2,2,1' && r.requests.map(x => x.url).join(' ') === '/mandate/m/export?after=0&limit=2 /mandate/m/export?after=2&limit=2 /mandate/m/export?after=4&limit=2', JSON.stringify(r.requests.map(x => x.url)))
r = await stubbed([PAGE([EV(1)], 0)], () => pq.mandate.exportAll('m'))
check('exportAll: a nextAfter that does not advance stops with an error', r.err instanceof PQAuthError && /did not advance/.test(r.err.message), String(r.err))
r = await stubbed([{ success: true, projectId: 'p', keys: [], count: 0 }], () => pq.mandate.publicKeys())
check('publicKeys: GET /public-keys', r.requests[0].method === 'GET' && r.requests[0].url === '/public-keys' && r.requests[0].apiKey === API_KEY, r.requests[0].url)

// ─── 2. Real receipts and a real export ─────────────────────────────────────

section('2. Real receipts and a real export, captured from FIPSign')
const R = FX.receipts
const KEYS_LIST = FX.publicKeysAfterRotation
for (const [name, rc] of Object.entries(R)) {
  if (name === 'suspendedAfterRotation') continue
  const c = await verifyMandateReceipt(rc, { publicKey: KEY_A.publicKey })
  check(`receipt "${name}" (event ${rc.event.seq}, ${rc.event.type}) is valid with the saved public key`, c.valid && c.problems.length === 0 && c.keyTrust === 'pinned' && c.projectId === FX.projectId && c.mandateId === FX.mandateId && c.event.hash === rc.event.hash && rc.keyFingerprint === KEY_A.fingerprint, JSON.stringify(c))
}
let c = await verifyMandateReceipt({ success: true, receipt: R.granted }, { pinFingerprint: KEY_A.fingerprint, keys: [KEY_A.publicKey] })
check('the whole answer, and a pinned fingerprint with the key from a list', c.valid, JSON.stringify(c))
c = await verifyMandateReceipt(R.suspendedAfterRotation, { publicKey: KEY_B.publicKey })
check('a receipt signed after the rotation is valid with the new key', c.valid && R.suspendedAfterRotation.keyFingerprint === KEY_B.fingerprint, JSON.stringify(c))
c = await verifyMandateReceipt(R.suspendedAfterRotation, { publicKey: KEY_A.publicKey })
check('...and not with the old one', !c.valid && c.problems.some(p => /not one of the keys you trust/.test(p)), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { publicKey: KEY_B.publicKey })
check('a receipt of the old key is not valid with only the new key', !c.valid && c.problems.some(p => /not one of the keys you trust/.test(p)), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { publicKey: [KEY_B.publicKey, KEY_A.publicKey] })
check('...it is with both keys given', c.valid, JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { pinFingerprint: KEY_A.fingerprint, keys: KEYS_LIST.keys })
check('the old receipt, with the fingerprint pinned and the keys of GET /public-keys (the retired one included)', c.valid && c.keyTrust === 'pinned', JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { pinFingerprint: KEY_A.fingerprint, keys: KEYS_LIST.keys.filter(k => k.status === 'current') })
check('pinned, but the list does not have that key -> not valid, says so', !c.valid && c.problems.some(p => p.includes(`no key with fingerprint ${KEY_A.fingerprint}`)), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { pinFingerprint: KEY_B.fingerprint, keys: KEYS_LIST.keys })
check('pinning the other key, with the whole list -> not valid', !c.valid, JSON.stringify(c))
const swappedList = KEYS_LIST.keys.map(k => (k.fingerprint === KEY_A.fingerprint ? { ...k, publicKey: KEY_B.publicKey } : k))
c = await verifyMandateReceipt(R.emitted, { pinFingerprint: KEY_A.fingerprint, keys: swappedList })
check('a list that puts the key B under the fingerprint of A is not believed (the fingerprint is computed from the key)', !c.valid && c.problems.some(p => /no key with fingerprint/.test(p)), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { keys: KEYS_LIST.keys })
check('a list of keys without a pin or a public key: nothing is trusted -> not valid', !c.valid && c.problems.length === 1 && /no key to trust/.test(c.problems[0]), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted)
check('no key at all -> not valid', !c.valid && /no key to trust/.test(c.problems[0]), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { publicKey: KEY_A.publicKey, expect: { projectId: FX.projectId, mandateId: FX.mandateId } })
check('expect with the right project and mandate -> valid', c.valid, JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { publicKey: KEY_A.publicKey, expect: { projectId: 'prj_other' } })
check('expect.projectId of another project -> not valid', !c.valid && c.problems.some(p => /not prj_other/.test(p)), JSON.stringify(c))
c = await verifyMandateReceipt(R.emitted, { publicKey: KEY_A.publicKey, expect: { mandateId: 'mdt_other' } })
check('expect.mandateId of another mandate -> not valid', !c.valid && c.problems.some(p => /not mdt_other/.test(p)), JSON.stringify(c))

// every way of altering a receipt
const altered = (mut) => { const x = clone(R.granted); mut(x); return x }
const bad = async (name, receipt, pattern) => {
  const res = await verifyMandateReceipt(receipt, { publicKey: KEY_A.publicKey })
  check(name, !res.valid && (pattern === undefined || res.problems.some(p => pattern.test(p))), JSON.stringify(res.problems))
}
await bad('an event body edited (the cost)', altered(x => { x.event.body = x.event.body.replace(/"cost":\d+/, '"cost":0') }), /hash is not sha256|does not match/)
await bad('an event body edited and its hash recomputed: the signed hash no longer fits', altered(x => { x.event.body = x.event.body.replace(/"cost":\d+/, '"cost":0'); x.event.hash = sha(`${x.event.prevHash}\n${x.event.body}`) }), /not about the event/)
await bad('prevHash changed', altered(x => { x.event.prevHash = '1' + x.event.prevHash.slice(1) }), /hash is not sha256/)
await bad('hash changed', altered(x => { x.event.hash = '1' + x.event.hash.slice(1) }), /hash is not sha256|not about the event/)
await bad('seq changed', altered(x => { x.event.seq = 99 }), /not about the event|does not match/)
await bad('type changed', altered(x => { x.event.type = 'verify_denied' }), /does not match/)
await bad('at changed', altered(x => { x.event.at += 1 }), /not about the event|does not match/)
await bad('the signature of another receipt', altered(x => { x.signature = R.denied.signature }), /does not verify/)
await bad('a signature with a byte changed', altered(x => { const s = Buffer.from(x.signature, 'base64'); s[10] ^= 1; x.signature = s.toString('base64') }), /does not verify/)
await bad('the signed text edited (another mandate)', altered(x => { x.signed = x.signed.replace(FX.mandateId, 'mdt_other') }), /does not verify|belongs to another/)
await bad('the signed text with a space added (not canonical)', altered(x => { x.signed = x.signed.replace('{"at"', '{ "at"') }), /does not verify|canonical/)
await bad('the signed text of a checkpoint (another kind)', altered(x => { x.signed = x.signed.replace('mandate.receipt', 'mandate.checkpoint') }), /does not verify|kind/)
await bad('an unknown algorithm', altered(x => { x.algorithm = 'ML-DSA-99' }), /unknown algorithm/)
await bad('another algorithm than the key has', altered(x => { x.algorithm = 'ML-DSA-87' }), /does not verify/)
await bad('another keyFingerprint', altered(x => { x.keyFingerprint = KEY_B.fingerprint }), /not one of the keys you trust/)
await bad('the signature field missing', altered(x => { delete x.signature }), /not complete/)
await bad('the signature that is not base64', altered(x => { x.signature = '***' }), /does not verify/)
await bad('the event of another receipt with this signature', altered(x => { x.event = clone(R.denied.event) }), /not about the event/)

// ─── 3. The real export ──────────────────────────────────────────────────────

section('3. The real export, before and after the key rotation')
const EX1 = FX.exportBeforeRotation, EX2 = FX.exportAfterRotation
let e = await verifyMandateExport(EX1, { publicKey: KEY_A.publicKey })
check('before the rotation, with the saved public key: valid, complete, 2 checkpoints, head matches', e.valid && e.complete && e.checkpoints === 2 && e.headChecked && e.sealedThrough === 8 && e.lastSeq === 9 && e.events === 9 && e.keyTrust === 'pinned' && e.projectId === FX.projectId && e.mandateId === FX.mandateId && e.problems.length === 0, JSON.stringify(e))
e = await verifyMandateExport(EX1, { pinFingerprint: KEY_A.fingerprint })
check('with only the fingerprint pinned (the key comes with the export)', e.valid && e.keyTrust === 'pinned' && e.checkpoints === 2, JSON.stringify(e))
e = await verifyMandateExport(EX1[0], { publicKey: KEY_A.publicKey })
check('the first page alone: valid, not complete, the checkpoint that covers it is there, the later ones are not', e.valid && !e.complete && e.events === 3, JSON.stringify(e))
e = await verifyMandateExport(EX1)
check('no key: not valid, nothing is trusted', !e.valid && /no key to trust/.test(e.problems[0]) && e.events === 0, JSON.stringify(e))
e = await verifyMandateExport(EX1, { publicKey: KEY_B.publicKey })
check('the wrong key: not valid', !e.valid && e.problems.some(p => /not one of the keys you trust/.test(p)), JSON.stringify(e.problems))
e = await verifyMandateExport(EX1, { pinFingerprint: 'cd'.repeat(32) })
check('a fingerprint that no key of the export has: not valid, says so', !e.valid && e.problems.some(p => /no key with fingerprint cdcd/.test(p)), JSON.stringify(e.problems))
e = await verifyMandateExport(EX1, { pinFingerprint: 'nope' })
check('a pin that is not 64 hex characters: not valid (it does not fall back to a weaker check)', !e.valid && e.problems.some(p => /64 hexadecimal/.test(p)), JSON.stringify(e.problems))
e = await verifyMandateExport(EX1.map(p => ({ ...p, publicKeys: p.publicKeys.map(k => ({ ...k, publicKey: KEY_B.publicKey })) })), { pinFingerprint: KEY_A.fingerprint })
check('an export whose list of keys was swapped for another key: the pinned fingerprint is not found', !e.valid && e.problems.some(p => /no key with fingerprint/.test(p)), JSON.stringify(e.problems))

e = await verifyMandateExport(EX2, { pinFingerprint: [KEY_A.fingerprint, KEY_B.fingerprint] })
check('after the rotation, both fingerprints pinned: valid, 2 checkpoints signed with A, head signed with B', e.valid && e.checkpoints === 2 && e.headChecked && e.lastSeq === 10 && !e.complete && e.sealedThrough === 8, JSON.stringify(e))
e = await verifyMandateExport(EX2, { publicKey: [KEY_A.publicKey, KEY_B.publicKey] })
check('...and with both public keys', e.valid, JSON.stringify(e))
e = await verifyMandateExport(EX2, { pinFingerprint: KEY_B.fingerprint })
check('only the new key: the checkpoints of the old one do not verify', !e.valid && e.problems.some(p => /^checkpoint \d+: the signing key/.test(p)), JSON.stringify(e.problems))
e = await verifyMandateExport(EX2, { pinFingerprint: KEY_A.fingerprint })
check('only the old key: the head, signed with the new one, does not verify', !e.valid && e.problems.some(p => /^head: the signing key/.test(p)), JSON.stringify(e.problems))
e = await pq.mandate.verifyExport(EX2)
check('mandate.verifyExport with no key: checks with the keys of the export and says keyTrust "fipsign"', e.valid && e.keyTrust === 'fipsign' && e.checkpoints === 2, JSON.stringify(e))
e = await pq.mandate.verifyExport(EX2, { publicKey: KEY_B.publicKey })
check('mandate.verifyExport with a public key is strict: only that key is trusted', !e.valid && e.keyTrust === 'pinned', JSON.stringify(e))

// every way of altering the export
const flatEvents = ex => ex.flatMap(p => p.events)
const badExport = async (name, pages, pattern, opts = { pinFingerprint: [KEY_A.fingerprint, KEY_B.fingerprint] }) => {
  const res = await verifyMandateExport(pages, opts)
  check(name, !res.valid && (pattern === undefined || res.problems.some(p => pattern.test(p))), JSON.stringify(res.problems))
}
let x = clone(EX2); x[0].events[1].body = x[0].events[1].body.replace(/"cost":\d+/, '"cost":0')
await badExport('an event body edited', x, /hash is not sha256/)
x = clone(EX2); x[0].events[0].body = x[0].events[0].body.replace('"budgetTotal":100', '"budgetTotal":999')
await badExport('the first event edited (the budget)', x, /hash is not sha256/)
x = clone(EX2); x[1].events.splice(1, 1)
await badExport('an event dropped from the middle', x, /does not follow|prevHash/)
x = clone(EX2); x[0].events.reverse()
await badExport('events out of order', x, /does not follow|prevHash/)
x = [EX2[0], EX2[2]]
await badExport('a whole page left out', x, /does not follow/)
x = clone(EX2); x[2].events.pop()
await badExport('the last event cut off the end', x, /head|missing/)
x = clone(EX2); x[2].events = []
await badExport('the last page emptied', x, /head|missing|does not follow/)
x = [clone(EX2[0]), clone(EX2[0]), ...clone(EX2).slice(1)]
await badExport('a page repeated', x, /does not follow|prevHash/)
x = clone(EX2); x[1].mandateId = 'mdt_other'
await badExport('a page of another mandate mixed in', x, /not all of the same mandate/)
// the history rewritten with a recomputed chain (needs no secret): the checkpoints and the head no longer match
const rewritten = pages => {
  const out = clone(pages)
  let prev = ZERO
  for (const ev of flatEvents(out)) {
    if (ev.seq === 2) { const b = JSON.parse(ev.body); b.cost = 0; ev.body = ser(b) }
    ev.prevHash = prev; ev.hash = sha(`${prev}\n${ev.body}`); prev = ev.hash
  }
  return out
}
await badExport('the history rewritten from event 2 with the chain recomputed: the checkpoint no longer fits', rewritten(EX2), /sealed|checkpoint/)
// an event after the last checkpoint rewritten: only the signed head and a receipt can catch that
x = clone(EX2); { const last = x[2].events[x[2].events.length - 1]; const b = JSON.parse(last.body); b.correlationId = 'forged'; last.body = ser(b); last.hash = sha(`${last.prevHash}\n${last.body}`) }
await badExport('the last event rewritten with its hash recomputed: the signed head no longer fits', x, /head/)
x = clone(EX2); x[2].head.seq += 1
await badExport('the head changed', x, /head/)
x = clone(EX2); x[2].head.signature = EX2[0].head.signature
await badExport('the signature of another head', x, /head: the signature does not verify|head/)
x = clone(EX2); { const cp = flatEvents(x).find(ev => ev.type === 'checkpoint'); const b = JSON.parse(cp.body); b.coversHash = ZERO; cp.body = ser(b); cp.hash = sha(`${cp.prevHash}\n${cp.body}`) }
await badExport('a checkpoint that covers another hash', x, /not the one FIPSign sealed|prevHash|checkpoint/)
x = clone(EX2); { const cp = flatEvents(x).find(ev => ev.type === 'checkpoint'); const b = JSON.parse(cp.body); b.signature = EX2[2].head.signature; cp.body = ser(b); cp.hash = sha(`${cp.prevHash}\n${cp.body}`) }
await badExport('a checkpoint with a signature that is not its own', x, /prevHash|checkpoint/)
x = clone(EX2); x[2].head = null; x[1].head = null; x[0].head = null
e = await verifyMandateExport(x, { pinFingerprint: [KEY_A.fingerprint, KEY_B.fingerprint] })
check('an export without a head is still checked (chain and checkpoints), with no head verified', e.valid && !e.headChecked && e.checkpoints === 2, JSON.stringify(e))
x = clone(EX2); x.forEach(p => { p.events = p.events.filter(ev => ev.seq > 4) })
e = await verifyMandateExport(x, { pinFingerprint: [KEY_A.fingerprint, KEY_B.fingerprint] })
check('an export that starts at event 5 (events 1..4 not part of it): a note, not a failure; the later chain and checkpoint still check', e.valid && e.notes.some(n => /starts at event 5/.test(n)) && e.notes.some(n => /checkpoint 5 covers event 4/.test(n)) && e.checkpoints === 1 && !e.complete, JSON.stringify(e))

// ─── 4. Logs made here ───────────────────────────────────────────────────────

section('4. Logs made here with a fresh project key')
const DSA = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 }
function makeProject(algorithm = 'ML-DSA-65', projectId = 'prj_' + Math.random().toString(16).slice(2, 10)) {
  const dsa = DSA[algorithm]
  const kp  = dsa.keygen(crypto.getRandomValues(new Uint8Array(32)))
  const fingerprint = sha(Buffer.from(kp.publicKey))
  const seal = (kind, mandateId, seq, hash, at) => {
    const signed = ser({ v: 1, kind, projectId, mandateId, seq, hash, at })
    return { signed, signature: b64(dsa.sign(new TextEncoder().encode('FIPSIGN-MANDATE-v1\n' + signed), kp.secretKey)), algorithm, keyFingerprint: fingerprint }
  }
  const signRaw = text => b64(dsa.sign(new TextEncoder().encode('FIPSIGN-MANDATE-v1\n' + text), kp.secretKey))
  return { algorithm, publicKey: b64(kp.publicKey), fingerprint, projectId, seal, signRaw }
}
// A chain: `specs` are { type, at, fields } or { checkpoint: true, at }; a checkpoint seals the event before it.
function makeLog(project, mandateId, specs) {
  const events = []
  let prev = ZERO
  specs.forEach((sp, i) => {
    const seq = i + 1
    let fields = sp.fields ?? {}
    if (sp.checkpoint) {
      const covered = events[events.length - 1]
      const s = project.seal('mandate.checkpoint', mandateId, covered.seq, covered.hash, sp.at)
      fields = { projectId: project.projectId, coversSeq: covered.seq, coversHash: covered.hash, signature: s.signature, keyFp: s.keyFingerprint, alg: s.algorithm }
    }
    const type = sp.checkpoint ? 'checkpoint' : sp.type
    const body = ser({ v: 1, mandateId, seq, type, at: sp.at, ...fields })
    const hash = sha(`${prev}\n${body}`)
    events.push({ seq, type, at: sp.at, prevHash: prev, hash, body })
    prev = hash
  })
  return events
}
const pagesOf = (project, mandateId, events, size, { head = true, keys } = {}) => {
  const pages = []
  for (let i = 0; i < events.length; i += size) {
    const chunk = events.slice(i, i + size)
    const last  = events[events.length - 1]
    const hs    = project.seal('mandate.export', mandateId, last.seq, last.hash, last.at + 1)
    pages.push({
      format: 'fipsign.mandate.export.v1', projectId: project.projectId, mandateId, generatedAt: last.at + 1, events: chunk, count: chunk.length,
      nextAfter: i + size < events.length ? chunk[chunk.length - 1].seq : null,
      head: head ? { seq: last.seq, hash: last.hash, at: last.at + 1, source: 'live', lastCheckpointSeq: 0, ...hs } : null,
      publicKeys: keys ?? [{ fingerprint: project.fingerprint, algorithm: project.algorithm, publicKey: project.publicKey, status: 'current', recordedAt: 1, retiredAt: null }],
    })
  }
  return pages
}
const T0 = 1_800_000_000
const SPEC = [
  { type: 'emitted', at: T0, fields: { agentId: 'añadir-ñandú', issuedBy: 'ops@example.com', scope: ['a', 'b'], budgetTotal: 10, correlationId: 'ticket-é-✓-😀' } },
  { type: 'verify_granted', at: T0 + 1, fields: { action: 'a', cost: 1 } },
  { type: 'verify_denied', at: T0 + 2, fields: { action: 'z', cost: 1, reason: 'scope_not_authorized' } },
  { checkpoint: true, at: T0 + 10 },
  { type: 'suspended', at: T0 + 11, fields: {} },
  { type: 'resumed', at: T0 + 12, fields: {} },
  { checkpoint: true, at: T0 + 20 },
]
for (const algorithm of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const P = makeProject(algorithm), M = 'mdt_' + algorithm.slice(-2)
  const events = makeLog(P, M, SPEC)
  const pages = pagesOf(P, M, events, 3)
  e = await verifyMandateExport(pages, { publicKey: P.publicKey })
  check(`${algorithm}: a log with 2 checkpoints and a signed head over 3 pages: valid, complete, non-ASCII text in the events`, e.valid && e.complete && e.checkpoints === 2 && e.headChecked && e.events === 7 && e.sealedThrough === 6 && pages.length === 3, JSON.stringify(e))
  const rc = { ...P.seal('mandate.receipt', M, 2, events[1].hash, events[1].at), event: events[1] }
  c = await verifyMandateReceipt(rc, { publicKey: P.publicKey, expect: { projectId: P.projectId, mandateId: M } })
  check(`${algorithm}: a receipt made here is valid`, c.valid && c.keyTrust === 'pinned', JSON.stringify(c))
  c = await verifyMandateReceipt({ ...rc, signature: b64(new Uint8Array(Buffer.from(rc.signature, 'base64').map((b, i) => (i === 5 ? b ^ 1 : b)))) }, { publicKey: P.publicKey })
  check(`${algorithm}: a receipt with one bit of the signature changed is not valid`, !c.valid, JSON.stringify(c))
}
{
  const P = makeProject(), M = 'mdt_x'
  const events = makeLog(P, M, SPEC)
  const pages = pagesOf(P, M, events, 100)
  e = await verifyMandateExport(pages, { publicKey: P.publicKey })
  check('one page: valid and complete', e.valid && e.complete && pages.length === 1, JSON.stringify(e))
  e = await verifyMandateExport(pagesOf(P, M, events.slice(0, 6), 100), { publicKey: P.publicKey })
  check('a log that does not end in a checkpoint: valid, not complete (the last events are protected only by the signed head)', e.valid && !e.complete && e.sealedThrough === 3 && e.lastSeq === 6, JSON.stringify(e))
  e = await verifyMandateExport(pagesOf(P, M, events.slice(0, 6), 100, { head: false }), { publicKey: P.publicKey })
  check('...and without a head either: still valid, nothing signed covers events 5 and 6', e.valid && !e.complete && !e.headChecked, JSON.stringify(e))
  e = await verifyMandateExport(pagesOf(P, M, events, 100).map(p => ({ ...p, head: { ...p.head, seq: 99 } })), { publicKey: P.publicKey })
  check('a head that says the log is longer than the export, while the last page says there is no more: not valid', !e.valid, JSON.stringify(e.problems))
  const longer = makeLog(P, M, [...SPEC, { type: 'revoked', at: T0 + 30, fields: {} }])
  const cut = pagesOf(P, M, longer, 100); cut[0].events = cut[0].events.slice(0, 7); cut[0].count = 7
  e = await verifyMandateExport(cut, { publicKey: P.publicKey })
  check('events cut off the end while the head is further on: not valid', !e.valid && e.problems.some(p => /events are missing at the end/.test(p)), JSON.stringify(e.problems))
  const mid = clone(pages); mid[0].events.splice(2, 2)
  e = await verifyMandateExport(mid, { publicKey: P.publicKey })
  check('events missing in the middle: not valid', !e.valid && e.problems.some(p => /does not follow/.test(p)), JSON.stringify(e.problems))
  const tail = pagesOf(P, M, events.slice(3), 100)
  e = await verifyMandateExport(tail, { publicKey: P.publicKey })
  check('an export that starts at event 4: a note says the earlier events are not checked, the rest is', e.notes.some(n => /starts at event 4/.test(n)) && !e.complete, JSON.stringify(e))
  const other = makeProject()
  e = await verifyMandateExport(pages, { publicKey: other.publicKey })
  check('another project key: not valid', !e.valid, JSON.stringify(e.problems))
  const forged = clone(pages); {
    // somebody who can write the database and has no key: rewrites event 2 and recomputes the chain
    const flat = flatEvents(forged); let prev = ZERO
    for (const ev of flat) { if (ev.seq === 2) { const b = JSON.parse(ev.body); b.cost = 0; ev.body = ser(b) } ev.prevHash = prev; ev.hash = sha(`${prev}\n${ev.body}`); prev = ev.hash }
  }
  e = await verifyMandateExport(forged, { publicKey: P.publicKey })
  check('a history rewritten with a recomputed chain and no key: not valid', !e.valid && e.problems.some(p => /checkpoint|head/.test(p)), JSON.stringify(e.problems))
  // somebody who also replaces the key: with the fingerprint pinned that fails, with keys taken from the export it does not
  const thief = makeProject('ML-DSA-65', P.projectId)
  const forgedAll = pagesOf(thief, M, makeLog(thief, M, SPEC.map((s, i) => (i === 1 ? { ...s, fields: { action: 'a', cost: 0 } } : s))), 100)
  e = await verifyMandateExport(forgedAll, { pinFingerprint: P.fingerprint })
  check('a log re-signed with another key, the fingerprint of the real key pinned: not valid (the pin is what makes the check independent of FIPSign)', !e.valid && e.problems.some(p => /no key with fingerprint/.test(p)), JSON.stringify(e.problems))
  e = await pq.mandate.verifyExport(forgedAll)
  check('...with nothing pinned it checks out, and says keyTrust "fipsign": that is what the answer means', e.valid && e.keyTrust === 'fipsign', JSON.stringify(e))
}

section('4b. Signed by the right key, but not what a receipt, a checkpoint or a head is')
{
  const P = makeProject(), M = 'mdt_k'
  const events = makeLog(P, M, SPEC)
  const ev = events[1]
  const stmt = over => ({ v: 1, kind: 'mandate.receipt', projectId: P.projectId, mandateId: M, seq: ev.seq, hash: ev.hash, at: ev.at, ...over })
  const signedReceipt = (text) => ({ signed: text, signature: P.signRaw(text), algorithm: P.algorithm, keyFingerprint: P.fingerprint, event: ev })
  c = await verifyMandateReceipt(signedReceipt(ser(stmt({}))), { publicKey: P.publicKey })
  check('control: the statement written the way FIPSign writes it is valid', c.valid, JSON.stringify(c))
  c = await verifyMandateReceipt(signedReceipt(ser(stmt({})).replace('{', '{ ')), { publicKey: P.publicKey })
  check('a statement with a space in it, signed by the right key: not valid, not in canonical form', !c.valid && c.problems.some(p => /canonical form/.test(p)), JSON.stringify(c.problems))
  c = await verifyMandateReceipt(signedReceipt(JSON.stringify(stmt({}))), { publicKey: P.publicKey })
  check('a statement with its keys in another order, signed by the right key: not valid, not in canonical form', !c.valid && c.problems.some(p => /canonical form/.test(p)), JSON.stringify(c.problems))
  c = await verifyMandateReceipt(signedReceipt(ser(stmt({ kind: 'mandate.checkpoint' }))), { publicKey: P.publicKey })
  check('a checkpoint statement presented as a receipt, signed by the right key: not valid, wrong kind', !c.valid && c.problems.some(p => /not of kind mandate.receipt/.test(p)), JSON.stringify(c.problems))
  c = await verifyMandateReceipt(signedReceipt(ser(stmt({ v: 2 }))), { publicKey: P.publicKey })
  check('a statement of another version: not valid', !c.valid && c.problems.some(p => /not of kind/.test(p)), JSON.stringify(c.problems))
  c = await verifyMandateReceipt(signedReceipt(ser(stmt({ seq: 3 }))), { publicKey: P.publicKey })
  check('a statement about another event, signed by the right key: not valid', !c.valid && c.problems.some(p => /not about the event/.test(p)), JSON.stringify(c.problems))
  c = await verifyMandateReceipt(signedReceipt(ser(stmt({ mandateId: 'mdt_other' }))), { publicKey: P.publicKey })
  check('a statement about another mandate than the event is of, signed by the right key: not valid', !c.valid && c.problems.some(p => /another mandate/.test(p)), JSON.stringify(c.problems))
  // a receipt signature reused as the signature of a checkpoint (same seq, hash and at), and a checkpoint reused as a head
  const swapped = clone(events)
  const cpIdx = swapped.findIndex(x => x.type === 'checkpoint')
  const cpBody = JSON.parse(swapped[cpIdx].body), covered = swapped[cpIdx - 1]
  cpBody.signature = P.signRaw(ser(stmt({ seq: covered.seq, hash: covered.hash, at: swapped[cpIdx].at })))
  let prev = swapped[cpIdx].prevHash
  swapped[cpIdx].body = ser(cpBody)
  for (const x2 of swapped.slice(cpIdx)) { x2.prevHash = prev; if (x2.seq === swapped[cpIdx].seq) x2.body = ser(cpBody); x2.hash = sha(`${prev}\n${x2.body}`); prev = x2.hash }
  e = await verifyMandateExport(pagesOf(P, M, swapped, 100, { head: false }), { publicKey: P.publicKey })
  check('a checkpoint signed with the statement of a receipt (the kinds cannot be swapped): not valid', !e.valid && e.problems.some(p => /checkpoint 4: the signature does not verify/.test(p)), JSON.stringify(e.problems))
  const asHead = pagesOf(P, M, events, 100)
  const last = events[events.length - 1]
  asHead[0].head = { ...asHead[0].head, ...{ signed: ser(stmt({ seq: last.seq, hash: last.hash, at: asHead[0].head.at })) } }
  asHead[0].head.signature = P.signRaw(asHead[0].head.signed)
  e = await verifyMandateExport(asHead, { publicKey: P.publicKey })
  check('a receipt statement presented as the head of an export: not valid, wrong kind', !e.valid && e.problems.some(p => /head: the statement is not of kind mandate.export/.test(p)), JSON.stringify(e.problems))
  const ghost = clone(events); ghost[1].body = ghost[1].body.replace('"seq":2', '"seq":7'); ghost[1].hash = sha(`${ghost[1].prevHash}\n${ghost[1].body}`)
  e = await verifyMandateExport(pagesOf(P, M, ghost, 100, { head: false }), { publicKey: P.publicKey })
  check('an event whose body says another seq than the event: not valid', !e.valid && e.problems.some(p => /body does not match the event/.test(p)), JSON.stringify(e.problems))
}

// ─── 5. Keys and the client's checks ─────────────────────────────────────────

section('5. Keys, and what the client method fetches')
const keysAnswer = KEYS_LIST
r = await stubbed([], () => pq.mandate.verifyReceipt(R.emitted, { publicKey: KEY_A.publicKey }))
check('verifyReceipt with a public key: valid, no request at all', r.out?.valid === true && r.out.keyTrust === 'pinned' && r.requests.length === 0, JSON.stringify(r.out ?? String(r.err)) + JSON.stringify(r.requests))
r = await stubbed([keysAnswer], () => pq.mandate.verifyReceipt(R.emitted, { pinFingerprint: KEY_A.fingerprint }))
check('verifyReceipt with a pinned fingerprint: one GET /public-keys, then valid and pinned', r.out?.valid === true && r.out.keyTrust === 'pinned' && r.requests.length === 1 && r.requests[0].url === '/public-keys', JSON.stringify(r.out ?? String(r.err)) + JSON.stringify(r.requests.map(q => q.url)))
r = await stubbed([], () => pq.mandate.verifyReceipt(R.emitted, { pinFingerprint: KEY_A.fingerprint, keys: keysAnswer.keys }))
check('verifyReceipt with a pin and the keys: no request', r.out?.valid === true && r.requests.length === 0, JSON.stringify(r.out ?? String(r.err)))
r = await stubbed([keysAnswer], () => pq.mandate.verifyReceipt(R.emitted))
check('verifyReceipt with nothing: one GET /public-keys, valid with the keys FIPSign lists, keyTrust "fipsign"', r.out?.valid === true && r.out.keyTrust === 'fipsign' && r.requests.length === 1, JSON.stringify(r.out ?? String(r.err)))
r = await stubbed([keysAnswer], () => pq.mandate.verifyReceipt({ ...R.emitted, signature: R.denied.signature }))
check('verifyReceipt with nothing, an altered receipt: not valid', r.out?.valid === false && r.out.keyTrust === 'fipsign', JSON.stringify(r.out ?? String(r.err)))
r = await stubbed([{ http: 401, body: { success: false, error: 'Invalid API key' } }], () => pq.mandate.verifyReceipt(R.emitted))
check('verifyReceipt when the keys cannot be fetched: a PQAuthError (it does not say "valid" or "invalid")', r.err instanceof PQAuthError && r.err.status === 401, String(r.err ?? JSON.stringify(r.out)))
r = await stubbed([{ success: true, projectId: 'p', keys: [], count: 0 }], () => pq.mandate.verifyReceipt(R.emitted))
check('verifyReceipt when the list of keys is empty: not valid, says there is no key', r.out?.valid === false && /no key/.test(r.out.problems[0]), JSON.stringify(r.out))
r = await stubbed([], () => pq.mandate.verifyExport(EX1))
check('verifyExport makes no request', r.out?.valid === true && r.requests.length === 0, JSON.stringify(r.out ?? String(r.err)))

const fp = await publicKeyFingerprint(KEY_A.publicKey)
check('publicKeyFingerprint gives the fingerprint FIPSign shows', fp === KEY_A.fingerprint && fp === sha(Buffer.from(KEY_A.publicKey, 'base64')), fp)
check('publicKeyFingerprint: SHA-256 of the key bytes, known answer', await publicKeyFingerprint('AQID') === '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81', '')
check('publicKeyFingerprint ignores white space around the key', await publicKeyFingerprint(`  ${KEY_A.publicKey}\n`) === KEY_A.fingerprint, '')
for (const junk of ['', '   ', '%%%', 5, null, undefined]) {
  let err = null
  try { await publicKeyFingerprint(junk) } catch (x2) { err = x2 }
  check(`publicKeyFingerprint(${JSON.stringify(junk)}) throws PQAuthError INVALID_PUBLIC_KEY`, err instanceof PQAuthError && err.code === 'INVALID_PUBLIC_KEY', String(err))
}

// ─── 6. They never throw ─────────────────────────────────────────────────────

section('6. They never throw')
const JUNK = [undefined, null, 0, 1, NaN, '', 'text', true, [], [null], {}, { receipt: null }, { events: null }, { event: {} },
  { signed: 1, signature: 2, algorithm: 3, keyFingerprint: 4, event: { seq: 'x' } }, { events: [{}], projectId: 'p', mandateId: 'm' },
  { events: [EV(1)], projectId: 'p', mandateId: 'm', head: 5 }, { events: [{ ...EV(1), body: 7 }], projectId: 'p', mandateId: 'm' }, [[]], [{ events: 'nope' }]]
let threw = 0, notFalse = 0
for (const j of JUNK) {
  for (const o of [undefined, null, {}, { publicKey: KEY_A.publicKey }, { pinFingerprint: KEY_A.fingerprint }, { publicKey: 5 }, { pinFingerprint: [1, 2] }, { keys: 'x' }, { expect: null }]) {
    for (const f of [verifyMandateReceipt, verifyMandateExport, (a, b) => pq.mandate.verifyExport(a, b)]) {
      try { const res = await f(j, o); if (res.valid !== false || !Array.isArray(res.problems) || res.problems.length === 0) notFalse++ } catch { threw++ }
    }
  }
}
check(`${JUNK.length * 9 * 3} calls with junk input: none throws, every one answers valid:false with a reason`, threw === 0 && notFalse === 0, `threw ${threw}, not false ${notFalse}`)

// ─── 7. The CommonJS build ───────────────────────────────────────────────────

section('7. CommonJS')
const cjs = createRequire(import.meta.url)('fipsign-sdk')
const cc = await cjs.verifyMandateReceipt(R.emitted, { publicKey: KEY_A.publicKey })
check('require("fipsign-sdk") has the three functions and they work', typeof cjs.verifyMandateExport === 'function' && typeof cjs.publicKeyFingerprint === 'function' && cc.valid === true, JSON.stringify(cc))

stub.close()
console.log(`\n${BOLD}${passed} passed, ${failed} failed${RESET}`)
process.exit(failed ? 1 : 0)
