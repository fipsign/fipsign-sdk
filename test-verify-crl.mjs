#!/usr/bin/env node
/**
 * ca.verifyCrl() - checks that a revocation list was signed by the CA, for PQCert and X.509 CAs.
 *
 * Offline: no API key, no network, no tokens. A stub FIPSign on localhost serves the lists.
 *
 * Usage:  npm run build && node test-verify-crl.mjs
 * (it imports 'fipsign-sdk', which inside this repo is the build in dist/)
 *
 * What it checks:
 *   - a real list of each kind, captured from FIPSign (test-verify-crl-fixtures.json): valid with its root, through
 *     ca.getCrl() and as the signed object itself;
 *   - every way of altering a list (hiding or adding a revocation, changing a field, moving generatedAt, a bad signature)
 *     makes it invalid, and so does the wrong root;
 *   - lists made here with a fresh CA key: empty, large, non-ASCII reasons, keys in any order;
 *   - it never throws, whatever it is given.
 */
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { PQAuth } from 'fipsign-sdk'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const GREEN = '\x1b[32m', RED = '\x1b[31m', BOLD = '\x1b[1m', RESET = '\x1b[0m'
let passed = 0, failed = 0
const pass = name => { passed++; console.log(GREEN + 'PASS' + RESET + '  ' + name) }
const fail = (name, why) => { failed++; console.log(RED + 'FAIL' + RESET + '  ' + name + '\n        ' + why) }
const check = (name, cond, why = '') => (cond ? pass(name) : fail(name, why))

const FX = JSON.parse(readFileSync(new URL('./test-verify-crl-fixtures.json', import.meta.url), 'utf8'))
const clone = x => JSON.parse(JSON.stringify(x))
const b64 = u8 => Buffer.from(u8).toString('base64')
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'))

// A serializer written for this test, apart from the SDK's: keys sorted at every level, arrays keep their order.
const ser = v => Array.isArray(v) ? '[' + v.map(ser).join(',') + ']'
  : (v !== null && typeof v === 'object') ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}'
  : JSON.stringify(v)

// ─── A stub FIPSign that serves one answer for GET /ca/crl ───────────────────

let answer = {}
const stub = createServer((req, res) => {
  req.resume()
  req.on('end', () => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(answer)) })
})
await new Promise(r => stub.listen(0, '127.0.0.1', r))
const pq = new PQAuth({ apiKey: 'pqa_' + '0'.repeat(64), baseUrl: `http://127.0.0.1:${stub.address().port}` })
const serve = a => { answer = a }

// ─── A CA made here (for lists that FIPSign did not sign) ────────────────────

function makeCa(id = 'ca_test_' + Math.random().toString(16).slice(2, 10)) {
  const kp = ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)))
  const root = { type: 'CA_ROOT', id, subject: 'Test CA', publicKey: b64(kp.publicKey), issuedAt: 1, algorithm: 'ML-DSA-65', standard: 'NIST FIPS 204', signature: 'x' }
  const signList = (revokedCerts, extra = {}) => {
    const payload = { caId: id, subject: 'Test CA', format: 'pqcert', algorithm: 'ML-DSA-65', generatedAt: Math.floor(Date.now() / 1000), revokedCerts, ...extra }
    return { ...payload, signature: b64(ml_dsa65.sign(new TextEncoder().encode(ser(payload)), kp.secretKey)) }
  }
  return { root, signList }
}

const invalid = async (name, crl, root, expect) => {
  const r = await pq.ca.verifyCrl(crl, root)
  check(name, r.valid === false && typeof r.error === 'string' && r.error.length > 0 && (!expect || expect.test(r.error)), JSON.stringify(r))
}

// ─── 1. Real lists captured from FIPSign ─────────────────────────────────────

for (const fmt of ['pqcert', 'x509']) {
  const { root, crl, revokedIds, notRevokedId } = FX[fmt]
  console.log(BOLD + `\n== 1. A real ${fmt} list from FIPSign` + RESET)
  const direct = await pq.ca.verifyCrl(crl, root)
  check(`${fmt}: the signed object is valid with its root, and generatedAt is the signed one`, direct.valid === true && direct.generatedAt === crl.generatedAt && direct.error === undefined, JSON.stringify(direct))
  serve({ success: true, crl, generatedAt: crl.generatedAt, verifyNote: 'x' })
  const list = await pq.ca.getCrl()
  check(`${fmt}: getCrl() keeps the signed object in raw and the flat entries in crl`, list.raw?.signature === crl.signature && list.raw.format === fmt && list.crl.length === 3 && list.caId === crl.caId, JSON.stringify(Object.keys(list)))
  const viaList = await pq.ca.verifyCrl(list, root)
  check(`${fmt}: the result of getCrl() is valid with the root`, viaList.valid === true && viaList.generatedAt === crl.generatedAt, JSON.stringify(viaList))
  check(`${fmt}: isCertRevoked finds the 3 revoked certs and not the other one`, revokedIds.every(id => pq.ca.isCertRevoked(id, list.crl)) && !pq.ca.isCertRevoked(notRevokedId, list.crl))
  check(`${fmt}: the non-ASCII reason arrived intact`, list.crl.some(e => e.reason === 'revocación 日本語 🔒 “quotes”'))
  const reordered = Object.fromEntries(Object.entries(clone(crl)).reverse())
  check(`${fmt}: the order of the keys in the object does not matter`, (await pq.ca.verifyCrl(reordered, root)).valid === true)

  console.log(BOLD + `\n== 2. Every alteration of the ${fmt} list is caught` + RESET)
  const mutations = {
    'the newest revocation removed (hiding one)': c => { c.revokedCerts.shift() },
    'the oldest revocation removed': c => { c.revokedCerts.pop() },
    'all revocations removed': c => { c.revokedCerts = [] },
    'a revocation added': c => { c.revokedCerts.push({ certId: 'cert_not_in_the_list', reason: null, revokedAt: 1 }) },
    'entries reordered': c => { c.revokedCerts.reverse() },
    'a certId changed': c => { c.revokedCerts[0].certId = c.revokedCerts[0].certId.slice(0, -1) + (c.revokedCerts[0].certId.endsWith('0') ? '1' : '0') },
    'a reason changed': c => { c.revokedCerts[0].reason = 'other' },
    'the non-ASCII reason changed by one character': c => { const e = c.revokedCerts.find(x => /日本語/.test(x.reason ?? '')); e.reason = e.reason.replace('🔒', '🔓') },
    'a revokedAt changed': c => { c.revokedCerts[0].revokedAt += 1 },
    'generatedAt moved (an old list passed off as new)': c => { c.generatedAt += 1 },
    'caId changed': c => { c.caId = c.caId + 'x' },
    'subject changed': c => { c.subject = 'Other CA' },
    'format changed': c => { c.format = fmt === 'pqcert' ? 'x509' : 'pqcert' },
    'algorithm changed': c => { c.algorithm = 'ML-DSA-87' },
    'a field added': c => { c.extra = true },
    'a field removed': c => { delete c.subject },
    'one byte of the signature flipped': c => { const s = unb64(c.signature); s[7] ^= 1; c.signature = b64(s) },
    'the signature truncated': c => { c.signature = b64(unb64(c.signature).slice(0, 3000)) },
    'the signature is not base64': c => { c.signature = '***not base64***' },
    'the signature is empty': c => { c.signature = '' },
    'the signature is missing': c => { delete c.signature },
  }
  for (const [what, mutate] of Object.entries(mutations)) {
    const c = clone(crl); mutate(c)
    await invalid(`${fmt}: ${what}`, c, root)
  }

  console.log(BOLD + `\n== 3. The ${fmt} list through getCrl(): what you read has to be what was signed` + RESET)
  { const l = clone(list); l.crl.shift(); await invalid('the entries in crl differ from the signed ones (one removed)', l, root, /not the signed ones/) }
  { const l = clone(list); l.crl[0].reason = 'edited'; await invalid('an entry in crl was edited', l, root, /not the signed ones/) }
  { const l = clone(list); l.generatedAt += 60; await invalid('generatedAt of the result differs from the signed one', l, root, /not the signed ones/) }
  { const l = clone(list); l.caId = 'ca_other'; await invalid('caId of the result differs from the signed one', l, root, /not the signed ones/) }
  { const l = clone(list); l.raw.revokedCerts.shift(); await invalid('the signed object inside the result was altered', l, root) }
}

// ─── 4. The wrong root ──────────────────────────────────────────────────────

console.log(BOLD + '\n== 4. The wrong root' + RESET)
{
  const { root, crl } = FX.pqcert
  const other = makeCa(root.id)           // same id, another key
  await invalid('pqcert list with the CA_ROOT of another CA that has the same id: bad signature', crl, other.root, /Invalid list signature/)
  await invalid('pqcert list with a CA_ROOT of another id: "not issued by this CA"', crl, makeCa('ca_someone_else').root, /not issued by this CA/)
  await invalid('pqcert list with a CA_CERT instead of the CA_ROOT', crl, { ...root, type: 'CA_CERT' }, /CA_ROOT/)
  await invalid('pqcert list with the root as a string', crl, JSON.stringify(root), /CA_ROOT/)
  await invalid('pqcert list with a PEM', crl, FX.x509.root, /CA_ROOT/)
  await invalid('pqcert list with no root', crl, undefined, /CA_ROOT/)
  await invalid('pqcert list with null as root', crl, null, /CA_ROOT/)
  await invalid('pqcert list with a root whose key is not base64', crl, { ...root, publicKey: '***' }, /not valid base64/)
  await invalid('pqcert list with a root whose key has the wrong size', crl, { ...root, publicKey: b64(new Uint8Array(100)) })
  const x = FX.x509
  await invalid('x509 list with a PQCert root object', x.crl, FX.pqcert.root, /PEM/)
  await invalid('x509 list with no root', x.crl, undefined, /PEM/)
  await invalid('x509 list with a string that is not a PEM', x.crl, 'hello', /could not be read/)
  await invalid('x509 list with an empty string as root', x.crl, '', /could not be read/)
  await invalid('x509 list with a truncated PEM', x.crl, x.root.slice(0, 200), /could not be read/)
  // an X.509 root that is not the one that signed it: the real PEM with one byte changed inside its public key
  const der = Buffer.from(x.root.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64')
  const keyAt = der.indexOf(Buffer.from([0x03, 0x82, 0x07, 0xa1, 0x00]))     // BIT STRING of 1953 bytes: the ML-DSA-65 key
  check('(the public key was found inside the root certificate)', keyAt > 0, String(keyAt))
  der[keyAt + 5 + 100] ^= 1
  const pemOther = '-----BEGIN CERTIFICATE-----\n' + der.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n'
  const r = await pq.ca.verifyCrl(x.crl, pemOther)
  check('x509 list with a root whose key was changed by one byte: invalid signature, no exception', r.valid === false && /Invalid list signature/.test(r.error ?? ''), JSON.stringify(r))
}

// ─── 5. Lists made here with a fresh CA key ──────────────────────────────────

console.log(BOLD + '\n== 5. Lists made here' + RESET)
{
  const ca = makeCa()
  const empty = ca.signList([])
  check('an empty list is valid', (await pq.ca.verifyCrl(empty, ca.root)).valid === true)
  const reasons = ['key compromise', null, 'revocación 日本語 🔒 “quotes” \\ back', '', 'x'.repeat(256), '\u0000 control \u001f', 'surrogate pair 𝄞']
  const entries = reasons.map((reason, i) => ({ certId: 'cert_' + i, reason, revokedAt: 1000 - i }))
  const withReasons = ca.signList(entries)
  check('reasons with non-ASCII, emoji, quotes, backslash, empty, control characters, null and 256 characters are valid', (await pq.ca.verifyCrl(withReasons, ca.root)).valid === true)
  serve({ success: true, crl: withReasons, generatedAt: withReasons.generatedAt, verifyNote: 'x' })
  check('the same through getCrl()', (await pq.ca.verifyCrl(await pq.ca.getCrl(), ca.root)).valid === true)
  const big = ca.signList(Array.from({ length: 5000 }, (_, i) => ({ certId: 'cert_' + i, reason: i % 3 ? null : 'r' + i, revokedAt: 5000 - i })))
  const t0 = Date.now(); const rb = await pq.ca.verifyCrl(big, ca.root)
  check('a list of 5000 entries is valid (' + (Date.now() - t0) + ' ms)', rb.valid === true)
  const wrong = ca.signList(entries, { subject: 'Test CA' }); wrong.revokedCerts[0].reason = 'x'
  await invalid('a list edited after signing is invalid', wrong, ca.root)
  const withAge = await pq.ca.verifyCrl(ca.signList([]), ca.root)
  check('generatedAt lets the caller judge how old the list is', withAge.valid && Math.abs(Date.now() / 1000 - withAge.generatedAt) < 5)
}

// ─── 6. What an unsigned list gives ──────────────────────────────────────────

console.log(BOLD + '\n== 6. A list that is not signed' + RESET)
{
  const flat = { success: true, caId: 'ca_x', subject: 'S', crl: [{ certId: 'cert_1', revokedAt: 5, reason: null }], generatedAt: 10 }
  serve(flat)
  const list = await pq.ca.getCrl()
  check('a plain array answer is still read by getCrl() (caId, subject, entries, generatedAt, no raw)', list.caId === 'ca_x' && list.crl.length === 1 && list.generatedAt === 10 && list.raw === undefined, JSON.stringify(list))
  check('isCertRevoked still works on it', pq.ca.isCertRevoked('cert_1', list.crl) === true)
  await invalid('verifyCrl says it is not signed', list, makeCa('ca_x').root, /not signed/)
  await invalid('the same for the bare entries', { caId: 'ca_x', subject: 'S', crl: flat.crl, generatedAt: 10 }, makeCa('ca_x').root, /not signed/)
}

// ─── 7. It never throws ──────────────────────────────────────────────────────

console.log(BOLD + '\n== 7. It never throws' + RESET)
{
  const root = FX.pqcert.root
  const junk = [undefined, null, 0, 42, 'text', true, [], [1, 2], {}, { signature: 1 }, { signature: 'abc' }, { signature: 'abc', revokedCerts: 'no' },
    { signature: 'abc', revokedCerts: [], caId: 1 }, { raw: null }, { raw: 'x' }, { raw: {} }, { raw: { signature: 5 } }, () => 1, Symbol('s')]
  let threw = null, allInvalid = true
  for (const j of junk) {
    try { const r = await pq.ca.verifyCrl(j, root); if (r.valid !== false || !r.error) allInvalid = false } catch (e) { threw = e; break }
  }
  check('19 kinds of wrong input: no exception, always { valid: false, error }', threw === null && allInvalid, String(threw))
  let threwRoot = null
  for (const rt of [undefined, null, 0, [], {}, () => 1, Symbol('s'), { type: 'CA_ROOT' }, { type: 'CA_ROOT', id: FX.pqcert.crl.caId }]) {
    try { const r = await pq.ca.verifyCrl(FX.pqcert.crl, rt); if (r.valid !== false) threwRoot = new Error('valid with a bad root') } catch (e) { threwRoot = e; break }
  }
  check('9 kinds of wrong root: no exception, never valid', threwRoot === null, String(threwRoot))
}

stub.close()
console.log('\n' + BOLD + `${passed} passed, ${failed} failed` + RESET)
process.exit(failed ? 1 : 0)
