/**
 * fipsign-sdk
 *
 * Post-quantum signing SDK for Node.js and the browser.
 * Uses ML-DSA-44, ML-DSA-65, or ML-DSA-87 (NIST FIPS 204) — resistant to quantum computers.
 *
 * Sign anything: users, orders, documents, devices, events.
 * The only required field is `sub` — any string identifying the entity.
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PQAuthOptions {
  apiKey:       string
  baseUrl?:     string
  timeout?:     number
  localVerify?: boolean
  projectId?:   string
}

export interface SignOptions {
  sub:               string
  expiresInSeconds?: number
  /**
   * Any additional fields are stored in the token payload and returned on verify().
   * Field names starting with `_` are reserved for the server. `_iss` (issuer) is set
   * automatically and ignored if provided; any other `_` field makes the request fail with
   * HTTP 400 (for example `_mandate`, which only Mandate tokens carry).
   */
  [key: string]:     unknown
}

export interface PQToken {
  payload:   string
  signature: string
  algorithm: string
  issuedAt:  number
}

export interface SignResult {
  token: PQToken
  meta: {
    algorithm:        string
    standard:         string
    quantumResistant: boolean
    expiresIn:        number
    issuedFor:        string
    projectId:        string
    tokenCost:        number
    source:           'free' | 'pack' | 'free+pack'
  }
  usage: {
    freeRemaining:  number
    packRemaining:  number
    totalRemaining: number
    month:          string
  }
}

/**
 * Why verify() answered `valid: false`.
 *
 * - `'rejected'`        FIPSign looked at the token and it is not acceptable: bad signature, expired, revoked,
 *                       malformed, issued for another project, or a Mandate token. Answer 401.
 * - `'rate_limited'`    Your API key sent too many requests in the current minute. The token was NOT checked:
 *                       wait `retryAfter` seconds and try again.
 * - `'quota_exhausted'` Your free tokens and your packs are used up. The token was NOT checked and waiting
 *                       does not help: buy a pack from the dashboard.
 * - `'unavailable'`     FIPSign could not answer: timeout, network failure, a server error, or an invalid API key.
 *                       The token was NOT checked.
 *
 * Only `'rejected'` says something about the token. Do not log a user out because of the other three.
 */
export type VerifyFailure = 'rejected' | 'rate_limited' | 'quota_exhausted' | 'unavailable'

export interface VerifyResult {
  valid:   boolean
  payload: TokenPayload | null
  error?:  string
  local?:  boolean
  /** Why `valid` is false. Absent when `valid` is true. See VerifyFailure. */
  failure?:    VerifyFailure
  /** Seconds to wait before trying again. Only present with `failure: 'rate_limited'`. */
  retryAfter?: number
}

export interface TokenPayload {
  sub: string
  iat: number
  exp: number
  [key: string]: unknown
}

export interface RevokeResult {
  success:   boolean
  message:   string
  revokedAt: number
  sub:       string
  expiresAt: number
  note:      string
}

export interface UsageResult {
  current: {
    month:          string
    freeUsed:       number
    freeRemaining:  number
    freeLimit:      number
    packRemaining:  number
    totalRemaining: number
  }
  monthlyHistory: {
    month:      string
    tokensUsed: number
    fromFree:   number
    fromPack:   number
  }[]
  packs: {
    id:              string
    packType:        string
    tokensPurchased: number
    purchasedAt:     number
    paymentRef:      string | null
  }[]
  developer: { email: string }
  note:       string
}

export type WebhookEvent =
  | 'token.signed'
  | 'token.rejected'
  | 'token.revoked'
  | 'limit.warning'
  | 'limit.reached'

export interface HealthResult {
  status:           string
  algorithm:        string
  standard:         string
  quantumResistant: boolean
  version:          string
}

// ─── Certificate Authority types ──────────────────────────────────────────────

export interface PQCert {
  type:       'CA_ROOT' | 'CA_CERT'
  id:         string
  subject:    string
  publicKey:  string
  caId?:      string
  issuedAt:   number
  expiresAt?: number
  algorithm:  'ML-DSA-65'
  standard:   'NIST FIPS 204'
  meta?:      Record<string, unknown>
  signature:  string
}

export interface CaIssueCertOptions {
  subject:          string
  publicKey:        string
  expiresInSeconds: number
  meta?:            Record<string, unknown>
}

export interface CaIssueCertResult {
  certificate: PQCert | string  // PQCert para formato pqcert, string PEM para formato x509
  meta: {
    certId:    string
    caId:      string
    subject:   string
    issuedAt:  number
    expiresAt: number
    algorithm: string
    standard:  string
    format?:   string  // 'pqcert' | 'x509' — present for x509 CAs
    sizeNote?: string  // x509 only: size advisory
    caExpiry?: {       // present only when expiresInSeconds was truncated to fit CA root lifetime
      truncated:                  boolean
      requestedExpiresInSeconds:  number
      resolvedExpiresInSeconds:   number
    }
  }
  usage: {
    freeRemaining:  number
    packRemaining:  number
    totalRemaining: number
  }
}

export interface CaRevokeCertResult {
  certId:    string
  revokedAt: number
  reason:    string | null | undefined  // null si no se proveyó razón, undefined para CAs PQCert
  format?:   string  // 'x509' — present for x509 CAs only
  usage: {
    freeRemaining:  number
    packRemaining:  number
    totalRemaining: number
  }
}

export interface CaCertStatus {
  revoked:   boolean
  expired:   boolean
  revokedAt: number | null
  expiresAt: number
}

export interface CaGetCertResult {
  certificate: PQCert | string  // PQCert para formato pqcert, string PEM para formato x509
  status:      CaCertStatus
  meta?: {     // x509 only: additional certificate metadata
    certId:    string
    caId:      string
    subject:   string
    format:    string
    algorithm: string
  }
}

export interface CrlEntry {
  certId:    string
  revokedAt: number
  reason:    string | null
}

export interface CaGetCrlResult {
  caId:        string
  subject:     string
  crl:         CrlEntry[]
  generatedAt: number
  raw?:        Record<string, unknown>  // the full signed list (SignedCrl), the one ca.verifyCrl() checks
}

/**
 * The revocation list as the CA signs it: the `crl` field of the answer of GET /ca/crl, kept in `raw` by ca.getCrl().
 * The signature is ML-DSA-65 over the canonical JSON of this object without `signature` (keys sorted at every level).
 */
export interface SignedCrl {
  caId:         string
  subject:      string
  format:       'pqcert' | 'x509'
  algorithm:    'ML-DSA-65'
  generatedAt:  number
  revokedCerts: CrlEntry[]
  signature:    string  // base64
}

export interface VerifyCrlResult {
  valid:        boolean
  /**
   * Unix time (seconds) at which the CA generated and signed the list. Only when `valid`. The signature covers it, so it
   * cannot be moved forward: how old a list you are willing to accept is up to you (`Date.now() / 1000 - generatedAt`).
   */
  generatedAt?: number
  error?:       string
}

export interface VerifyCertResult {
  valid:  boolean
  cert?:  PQCert | string  // PQCert para pqcert, string PEM para x509
  error?: string
}

// ─── Mandate types ────────────────────────────────────────────────────────────

/**
 * `status` only tracks what was done to a mandate: it is never "expired". Whether a mandate
 * has expired is told by `expiresAt` and `expiresInSeconds` (0 once it has expired).
 */
export type MandateStatus = 'active' | 'suspended' | 'revoked'

export interface Mandate {
  id:               string
  agentId:          string
  issuedBy:         string
  scopeOriginal:    string[]
  scopeCurrent:     string[]
  budgetTotal:      number
  budgetConsumed:   number
  /** Always 0 when `budgetTotal` is 0 (unlimited): use `budgetConsumed` to see the usage. */
  budgetRemaining:  number
  status:           MandateStatus
  issuedAt:         number
  expiresAt:        number
  /** Seconds left until `expiresAt`; 0 once the mandate has expired. */
  expiresInSeconds: number
  updatedAt:        number
  /** true when the mandate was emitted with `agentPublicKey`: every verify then needs the agent's signature. */
  requiresAgentSignature: boolean
}

export interface MandateEmitOptions {
  agentId:          string
  issuedBy:         string
  scope:            string[]
  budgetTotal:      number
  expiresInSeconds: number
  /**
   * Optional proof of possession. Base64 ML-DSA public key of the agent (any of the three
   * variants; generateAgentKeyPair() makes one). When set, every mandate.verify() must also carry an
   * `agentSignature` made with the matching private key (see signAgentCall()). The private key
   * never reaches FIPSign. Without it the mandate is a plain bearer token.
   */
  agentPublicKey?:  string
}

export interface MandateEmitResult {
  mandate: {
    id:          string
    agentId:     string
    issuedBy:    string
    scope:       string[]
    budgetTotal: number
    expiresAt:   number
    status:      MandateStatus
    token:       PQToken
    /** Present (true) only when the mandate was emitted with `agentPublicKey`. */
    requiresAgentSignature?: true
  }
  usage: {
    freeRemaining:  number
    packRemaining:  number
    totalRemaining: number
    month:          string
  }
}

/**
 * Reasons for a denied mandate.verify(). The type stays open on purpose: failures that never
 * reach the mandate checks (invalid API key, rate limit, network error) put their own message in `reason`.
 */
export type MandateDenyReason =
  | 'invalid_signature'
  | 'mandate_expired'
  | 'mandate_revoked'
  | 'mandate_suspended'
  | 'scope_not_authorized'
  | 'budget_exhausted'
  | 'agent_signature_required'
  | 'agent_signature_invalid'
  | 'agent_signature_mismatch'
  | 'agent_signature_replayed'

/**
 * Why mandate.verify() answered `result: 'denied'`. The values of VerifyFailure, plus `'outcome_unknown'`.
 *
 * - `'rejected'`        FIPSign looked at the call and refused it (`reason` says why: scope, budget, expired, revoked,
 *                       suspended, agent signature...) or the request was not well formed. Nothing was consumed.
 * - `'rate_limited'`    Your API key sent too many requests in the current minute. Nothing was consumed:
 *                       wait `retryAfter` seconds and try again.
 * - `'quota_exhausted'` Your free tokens and your packs are used up. Nothing was consumed (the mandate budget is given
 *                       back) and waiting does not help: buy a pack from the dashboard.
 * - `'unavailable'`     FIPSign answered but could not check the call (for example, an invalid API key). Nothing was consumed.
 * - `'outcome_unknown'` NO usable answer arrived: timeout, network failure, an answer that could not be read, or a server
 *                       error. FIPSign may have granted the call, used up its budget and charged its tokens without you
 *                       ever hearing about it. Do not act as if it was granted and do not send it again blindly: with
 *                       `agentSignature`, send the SAME call again while the signature is still valid (`granted` = it is
 *                       applied now, once; `agent_signature_replayed` = it was applied the first time); without one, compare
 *                       `budgetConsumed` of mandate.get(id) with the value you had before. See Mandate 02c in the guide.
 *
 * Decide on `failure`, not on the text of `reason`. A call that was not granted is always `result: 'denied'`, so code
 * that only checks `result !== 'granted'` keeps working: it never acts on a call that may not have been granted.
 */
export type MandateVerifyFailure = VerifyFailure | 'outcome_unknown'

export interface MandateVerifyResult {
  result:               'granted' | 'denied'
  reason?:              MandateDenyReason | (string & {})
  /** Why `result` is 'denied'. Absent when granted. See MandateVerifyFailure. */
  failure?:             MandateVerifyFailure
  /** Seconds to wait before trying again. Only present with `failure: 'rate_limited'`. */
  retryAfter?:          number
  actionMatched?:       string
  budgetRemaining?:     number
  expiresInSeconds?:    number
  authorizedScope?:     string[]
  budgetConsumedUnits?: number
  budgetTotalUnits?:    number
  usage?: {
    freeRemaining:  number
    packRemaining:  number
    totalRemaining: number
    month:          string
  }
}

export interface MandateVerifyOptions {
  /** Required when the mandate was emitted with `agentPublicKey`. Made by signAgentCall(); single use. */
  agentSignature?: PQToken
}

export interface MandatePatchResult {
  id:         string
  status:     MandateStatus
  scope?:     string[]
  updatedAt?: number
  /** Only present when suspend() is called on an already-suspended mandate. */
  message?:   string
}

export interface MandateGetResult {
  mandate: Mandate
}

export interface MandateListOptions {
  /** Page size. The server validates it (it sets the default and the maximum). */
  limit?:  number
  /** The `nextCursor` of the previous page, exactly as received. Omit it for the first page. */
  cursor?: string
}

export interface MandateListResult {
  mandates:   Mandate[]
  /** Number of mandates in THIS page. A page can hold fewer than `limit`, even none. */
  count:      number
  /** Pass it as `cursor` to get the next page. null on the last page. */
  nextCursor: string | null
}

// ─── Middleware types ─────────────────────────────────────────────────────────

export interface MiddlewareRequest {
  headers: { [key: string]: string | string[] | undefined }
}

export interface MiddlewareResponse {
  status:     (code: number) => MiddlewareResponse
  json:       (data: unknown) => void
  /** Used to send Retry-After with a 503. Express, and Fastify through @fastify/express, have it. */
  setHeader?: (name: string, value: string) => unknown
}

export type NextFunction = (err?: unknown) => void

// ─── Errors ───────────────────────────────────────────────────────────────────

export class PQAuthError extends Error {
  /**
   * The `code` field of the server's error answer, when it has one. Today: `'rate_limited'` (too many
   * requests in the current minute) or `'token_quota_exhausted'` (free tokens and packs used up).
   * `code` below stays `'API_ERROR'` for both.
   */
  public readonly serverCode?: string
  /** Seconds to wait, from the `Retry-After` header of the server's answer. Sent with `'rate_limited'`. */
  public readonly retryAfter?: number

  constructor(
    message: string,
    public readonly code: string,
    public readonly status?: number,
    extra?: { serverCode?: string; retryAfter?: number }
  ) {
    super(message)
    this.name = 'PQAuthError'
    this.serverCode = extra?.serverCode
    this.retryAfter = extra?.retryAfter
  }
}

// Retry-After as a whole number of seconds (the only form FIPSign sends); anything else is ignored.
function parseRetryAfter(value: string | null | undefined): number | undefined {
  const text = value?.trim()
  return text !== undefined && /^\d+$/.test(text) ? Number(text) : undefined
}

// The error for an answer that is not a success: keeps the server's `code` and Retry-After.
function apiError(
  status: number,
  data: { error?: string; code?: unknown } | null,
  retryAfter: number | undefined
): PQAuthError {
  return new PQAuthError(
    data?.error ?? `Request failed with status ${status}`,
    'API_ERROR',
    status,
    { serverCode: typeof data?.code === 'string' ? data.code : undefined, retryAfter }
  )
}

// True for the errors of fetching the public key (local verification): no answer, or an answer that is not the key.
function isNoAnswer(err: unknown): err is PQAuthError {
  return err instanceof PQAuthError && (err.code === 'NETWORK_ERROR' || err.code === 'TIMEOUT')
}

function noAnswerResult(err: PQAuthError): VerifyResult {
  const base = { valid: false, payload: null, error: err.message, local: true } as const
  if (err.status === 429) {
    return err.retryAfter === undefined
      ? { ...base, failure: 'rate_limited' }
      : { ...base, failure: 'rate_limited', retryAfter: err.retryAfter }
  }
  return { ...base, failure: 'unavailable' }
}

// What a failed POST /verify answer means: the token was refused, or FIPSign could not decide.
function classifyVerifyFailure(
  status: number,
  data: { valid?: unknown; code?: unknown } | null,
  retryAfter: number | undefined
): { failure: VerifyFailure; retryAfter?: number } {
  if (status === 429) {
    if (data?.code === 'token_quota_exhausted') return { failure: 'quota_exhausted' }
    return retryAfter === undefined ? { failure: 'rate_limited' } : { failure: 'rate_limited', retryAfter }
  }
  // 401 with "valid": false is a token that was looked at and refused. The other 401 (invalid API key)
  // has no "valid" field. 400 is a token object that is not well formed.
  if ((status === 401 && data?.valid === false) || status === 400) return { failure: 'rejected' }
  return { failure: 'unavailable' }
}

// What a POST /mandate/verify answer that is not "granted" means. FIPSign consumes nothing on a denial (403), a malformed
// request (400), an invalid API key (401), an unsupported content type (415) or a 429, so any other 4xx is the same.
// Anything else (a 5xx, or a status that should not happen) may have come after the call was applied: 'outcome_unknown'.
function classifyMandateVerifyFailure(
  status: number,
  data: { result?: unknown; code?: unknown } | null,
  retryAfter: number | undefined
): { failure: MandateVerifyFailure; retryAfter?: number } {
  if (status === 429) return classifyVerifyFailure(status, data, retryAfter)
  if (data?.result === 'denied' || status === 400) return { failure: 'rejected' }
  if (status >= 400 && status < 500) return { failure: 'unavailable' }
  return { failure: 'outcome_unknown' }
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes  = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

// A token payload is JSON text carried as base64 of its UTF-8 bytes (this is what the server does).
// atob()/btoa() alone only handle Latin-1, so accents, € or emoji would come out garbled or throw.
function encodePayloadJson(json: string): string {
  return toBase64(new TextEncoder().encode(json))
}

// Strict: bytes that are not valid UTF-8 throw instead of being silently replaced.
function decodePayloadJson(b64: string): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(fromBase64(b64))
}

// ─── Local token verification ─────────────────────────────────────────────────

function getMlDsa(algorithm: string) {
  switch (algorithm) {
    case 'ML-DSA-44': return ml_dsa44
    case 'ML-DSA-65': return ml_dsa65
    case 'ML-DSA-87': return ml_dsa87
    default: throw new PQAuthError(`Unsupported algorithm: ${algorithm}`, 'UNSUPPORTED_ALGORITHM')
  }
}

function verifyLocally(
  token: PQToken,
  publicKeyB64: string,
  expectedProjectId: string
): TokenPayload {
  const mlDsa     = getMlDsa(token.algorithm)
  const publicKey = fromBase64(publicKeyB64)
  const signature = fromBase64(token.signature)
  const message   = new TextEncoder().encode(token.payload)
  const isValid = mlDsa.verify(signature, message, publicKey)
  if (!isValid) {
    throw new PQAuthError(
      'Invalid signature — token was tampered with or not issued by this server',
      'INVALID_SIGNATURE'
    )
  }
  let payload: TokenPayload
  try {
    payload = JSON.parse(decodePayloadJson(token.payload))
  } catch {
    throw new PQAuthError('Invalid token payload — not valid UTF-8 JSON', 'INVALID_PAYLOAD')
  }
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp < now) {
    throw new PQAuthError(`Token expired ${now - payload.exp} seconds ago`, 'TOKEN_EXPIRED')
  }
  // ← NUEVO: validar issuer
  if (payload._iss !== expectedProjectId) {
    throw new PQAuthError(
      'Invalid signature — token was tampered with or not issued by this server',
      'ISSUER_MISMATCH'
    )
  }
  // A Mandate token is not a normal token: this function only checks signature and expiry, so it
  // would say "valid" even for a revoked or suspended mandate. Same rule as POST /verify on the server.
  if (payload._mandate === true) {
    throw new PQAuthError('This is a Mandate token. Verify it with mandate.verify()', 'MANDATE_TOKEN')
  }
  return payload
}

// ─── Local certificate verification ──────────────────────────────────────────

// Canonicaliza un objeto para firma — ordena keys recursivamente y serializa a JSON.
// Debe ser idéntico al canonicalizeJson del backend (ca.ts / ca-x509.ts / utils.ts).
function canonicalizeForSigning(obj: unknown): string {
  function sortedKeys(o: unknown): unknown {
    if (Array.isArray(o)) return o.map(sortedKeys)
    if (o !== null && typeof o === 'object') {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(o as Record<string, unknown>).sort()) {
        sorted[k] = sortedKeys((o as Record<string, unknown>)[k])
      }
      return sorted
    }
    return o
  }
  return JSON.stringify(sortedKeys(obj))
}

function verifyCertLocally(cert: PQCert, rootCert: PQCert): void {
  if (cert.type !== 'CA_CERT') {
    throw new PQAuthError('Expected a CA_CERT, got ' + cert.type, 'INVALID_CERT_TYPE')
  }
  if (rootCert.type !== 'CA_ROOT') {
    throw new PQAuthError('Expected a CA_ROOT, got ' + rootCert.type, 'INVALID_CERT_TYPE')
  }
  if (cert.caId !== rootCert.id) {
    throw new PQAuthError('Certificate was not issued by this CA', 'CA_MISMATCH')
  }

  const now = Math.floor(Date.now() / 1000)

  if (rootCert.expiresAt !== undefined && rootCert.expiresAt < now) {
    throw new PQAuthError(
      `Root CA certificate expired ${now - rootCert.expiresAt} seconds ago`,
      'ROOT_CERT_EXPIRED'
    )
  }

  if (cert.expiresAt !== undefined && cert.expiresAt < now) {
    throw new PQAuthError(
      `Certificate expired ${now - cert.expiresAt} seconds ago`,
      'CERT_EXPIRED'
    )
  }

  const { signature, ...certWithoutSig } = cert
  const canonical = canonicalizeForSigning(certWithoutSig)
  const msgBytes  = new TextEncoder().encode(canonical)
  const sigBytes  = fromBase64(signature)
  const pubKey    = fromBase64(rootCert.publicKey)

  const isValid = ml_dsa65.verify(sigBytes, msgBytes, pubKey)
  if (!isValid) {
    throw new PQAuthError(
      'Invalid certificate signature — not issued by this CA',
      'INVALID_CERT_SIGNATURE'
    )
  }
}

// ─── Local revocation list verification ──────────────────────────────────────

function crlFail(message: string, code: string): never {
  throw new PQAuthError(message, code)
}

// The ML-DSA-65 public key inside the PEM root certificate of an X.509 CA (the same extraction ca.verifyX509Cert() does).
async function x509RootPublicKey(rootPem: string): Promise<Uint8Array> {
  const { AsnConvert }  = await import('@peculiar/asn1-schema')
  const { Certificate } = await import('@peculiar/asn1-x509')
  const der  = fromBase64(rootPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''))
  const root = AsnConvert.parse(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength), Certificate)

  const OID_ML_DSA_65 = '2.16.840.1.101.3.4.3.18'
  if (root.signatureAlgorithm.algorithm !== OID_ML_DSA_65) {
    crlFail(`Unsupported root CA algorithm: ${root.signatureAlgorithm.algorithm}. Expected ML-DSA-65 (${OID_ML_DSA_65})`, 'UNSUPPORTED_ALGORITHM')
  }
  const spkiRaw = new Uint8Array(root.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey)
  if (spkiRaw.length === 1952) return spkiRaw
  if (spkiRaw.length === 1953 && spkiRaw[0] === 0x00) return spkiRaw.slice(1)  // skip the unused-bits byte
  return crlFail(`Unexpected public key size: ${spkiRaw.length} bytes (expected 1952 or 1953 for ML-DSA-65)`, 'INVALID_ROOT')
}

// Throws a PQAuthError unless `input` is a list signed by the CA whose root is `root`. Returns the signed generatedAt.
async function verifyCrlLocally(input: CaGetCrlResult | SignedCrl, root: PQCert | string): Promise<number> {
  if (input === null || typeof input !== 'object') {
    crlFail('Expected the result of ca.getCrl() or the signed list (the crl object of GET /ca/crl)', 'INVALID_CRL')
  }
  const obj = input as unknown as Record<string, unknown>

  // The signed object: the list itself (the REST answer's `crl` field), or the `raw` of a ca.getCrl() result.
  let signed: Record<string, unknown>
  if (typeof obj.signature === 'string') {
    signed = obj
  } else if (obj.raw !== null && typeof obj.raw === 'object' && typeof (obj.raw as Record<string, unknown>).signature === 'string') {
    signed = obj.raw as Record<string, unknown>
    // What the caller reads from the result (crl, caId, subject, generatedAt) has to be what was signed.
    if (
      obj.caId !== signed.caId || obj.subject !== signed.subject || obj.generatedAt !== signed.generatedAt ||
      !Array.isArray(obj.crl) || canonicalizeForSigning(obj.crl) !== canonicalizeForSigning(signed.revokedCerts)
    ) {
      crlFail('The entries of this result (crl, caId, subject, generatedAt) are not the signed ones (raw)', 'CRL_MISMATCH')
    }
  } else {
    return crlFail('This list is not signed: pass the result of ca.getCrl() or the signed crl object, from a FIPSign that signs the list', 'CRL_NOT_SIGNED')
  }

  if (typeof signed.caId !== 'string' || typeof signed.generatedAt !== 'number' || !Array.isArray(signed.revokedCerts)) {
    crlFail('Malformed list: caId, generatedAt and revokedCerts are required', 'INVALID_CRL')
  }
  if (signed.algorithm !== 'ML-DSA-65') {
    crlFail(`Unsupported algorithm: ${String(signed.algorithm)}. Expected ML-DSA-65`, 'UNSUPPORTED_ALGORITHM')
  }

  let publicKey: Uint8Array
  if (signed.format === 'pqcert') {
    if (root === null || typeof root !== 'object' || root.type !== 'CA_ROOT') {
      crlFail('This list is from a PQCert CA: pass its CA_ROOT certificate (the object returned when the CA was created)', 'INVALID_ROOT')
    }
    if (signed.caId !== root.id) {
      crlFail('This list was not issued by this CA', 'CA_MISMATCH')
    }
    try {
      publicKey = fromBase64(root.publicKey)
    } catch {
      return crlFail('The CA_ROOT certificate has a publicKey that is not valid base64', 'INVALID_ROOT')
    }
  } else if (signed.format === 'x509') {
    if (typeof root !== 'string') {
      crlFail('This list is from an X.509 CA: pass its root certificate in PEM form (a string)', 'INVALID_ROOT')
    }
    try {
      publicKey = await x509RootPublicKey(root)
    } catch (err) {
      if (err instanceof PQAuthError) throw err
      return crlFail('The root certificate could not be read: pass the PEM of the CA root certificate', 'INVALID_ROOT')
    }
  } else {
    return crlFail(`Unknown list format: ${String(signed.format)}`, 'INVALID_CRL')
  }

  const { signature, ...unsigned } = signed
  let isValid = false
  try {
    isValid = ml_dsa65.verify(fromBase64(signature as string), new TextEncoder().encode(canonicalizeForSigning(unsigned)), publicKey)
  } catch {
    isValid = false   // a signature or key of the wrong size or encoding is simply not a valid signature
  }
  if (!isValid) {
    crlFail('Invalid list signature — not signed by this CA', 'INVALID_CRL_SIGNATURE')
  }
  return signed.generatedAt as number
}

// ─── generateKeyPair ──────────────────────────────────────────────────────────

/**
 * Generate an ML-DSA-65 key pair for a device or entity.
 *
 * The entity keeps the secretKey private and passes the publicKey
 * to pqauth.ca.issue() to obtain a certificate. The CA only accepts ML-DSA-65 keys, which is
 * why this function has no options.
 *
 * For the key pair of a Mandate agent use generateAgentKeyPair() instead: it also offers
 * ML-DSA-44 and ML-DSA-87.
 *
 * @example
 * const { publicKey, secretKey } = await generateKeyPair()
 * // store secretKey securely on the device
 * const { certificate } = await pqauth.ca.issue({
 *   subject:          'device-serial-00123',
 *   publicKey,
 *   expiresInSeconds: 365 * 24 * 60 * 60,
 * })
 */
export async function generateKeyPair(): Promise<{ publicKey: string; secretKey: string }> {
  const seed = new Uint8Array(32)
  crypto.getRandomValues(seed)
  const keys = ml_dsa65.keygen(seed)
  seed.fill(0)
  return {
    publicKey: toBase64(keys.publicKey),
    secretKey: toBase64(keys.secretKey),
  }
}

// ─── generateAgentKeyPair (Mandate proof of possession) ───────────────────────

export type MlDsaVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'

export interface GenerateAgentKeyPairOptions {
  /** ML-DSA variant of the key pair. Default 'ML-DSA-65'. FIPSign accepts any of the three for a Mandate agent. */
  algorithm?: MlDsaVariant
}

export interface AgentKeyPair {
  /** Base64 public key. Pass it as `agentPublicKey` to pqauth.mandate.emit(). */
  publicKey: string
  /** Base64 private key. Keep it on the agent and never send it anywhere. Pass it to signAgentCall(). */
  secretKey: string
  /** The ML-DSA variant of this key pair. */
  algorithm: MlDsaVariant
}

/**
 * Generate the key pair of a Mandate agent (proof of possession).
 *
 * The agent keeps the secretKey; only the publicKey goes to FIPSign, as `agentPublicKey` of
 * pqauth.mandate.emit(). Unlike generateKeyPair() (which is for CA certificates and is always
 * ML-DSA-65) you can choose the variant here: ML-DSA-44, ML-DSA-65 (default) or ML-DSA-87.
 * Do not use these keys with pqauth.ca.issue(): the CA only accepts ML-DSA-65.
 *
 * @example
 * const { publicKey, secretKey } = await generateAgentKeyPair({ algorithm: 'ML-DSA-87' })
 * const { mandate } = await pqauth.mandate.emit({ ..., agentPublicKey: publicKey })
 * // later, on the agent: signAgentCall({ mandate: mandate.token, action, cost, secretKey })
 */
export async function generateAgentKeyPair(options: GenerateAgentKeyPairOptions = {}): Promise<AgentKeyPair> {
  const algorithm = options?.algorithm ?? 'ML-DSA-65'
  const mlDsa     = getMlDsa(algorithm)   // anything else fails with UNSUPPORTED_ALGORITHM
  const seed = new Uint8Array(32)
  crypto.getRandomValues(seed)
  const keys = mlDsa.keygen(seed)
  seed.fill(0)
  return {
    publicKey: toBase64(keys.publicKey),
    secretKey: toBase64(keys.secretKey),
    algorithm,
  }
}

// Size in bytes of the expanded ML-DSA private key, per variant. The three sizes are different, so the
// size of a secretKey tells which variant it is.
const AGENT_SECRET_KEY_VARIANT: Record<number, MlDsaVariant | undefined> = {
  2560: 'ML-DSA-44',
  4032: 'ML-DSA-65',
  4896: 'ML-DSA-87',
}

// ─── signAgentCall (Mandate proof of possession) ──────────────────────────────

// Default life of an agent signature. The server accepts at most 60 seconds and rejects anything longer
// as agent_signature_invalid; half of that leaves room for clock differences between agent and server.
const DEFAULT_AGENT_SIGNATURE_LIFETIME_SECONDS = 30

export interface SignAgentCallOptions {
  /** The mandate id (`mandate.id`) or the mandate token itself (the id is read from its `sub`). */
  mandate:           string | PQToken
  /** The action being requested: exactly what will be passed to mandate.verify(). */
  action:            string
  /** The cost being requested: exactly what will be passed to mandate.verify(). */
  cost:              number
  /** The agent's base64 private key, as returned by generateAgentKeyPair(). It is never sent anywhere. */
  secretKey:         string
  /**
   * ML-DSA variant of the key. Optional: it is detected from the size of the secretKey. If you pass it,
   * it must match the key, otherwise the call fails with INVALID_SECRET_KEY.
   */
  algorithm?:        MlDsaVariant
  /** Life of the signature in seconds. Default 30. The server rejects anything above its maximum (60). */
  expiresInSeconds?: number
}

/**
 * Sign one Mandate call with the agent's private key (proof of possession).
 *
 * Use it on the agent's side; no API key is needed and the private key never leaves the agent.
 * The result goes to the service that calls `pqauth.mandate.verify(token, action, cost, { agentSignature })`.
 *
 * The signature covers this exact mandate, action and cost, lives a few seconds and can be used
 * ONCE (the server remembers it): make a new one for every call.
 *
 * The ML-DSA variant (44, 65 or 87) is detected from the secretKey: you do not have to say it.
 *
 * @example
 * const { publicKey, secretKey } = await generateAgentKeyPair()   // once; keep secretKey on the agent
 * // ...emit the mandate with agentPublicKey: publicKey...
 * const agentSignature = await signAgentCall({ mandate: mandate.token, action: 'send_reply', cost: 1, secretKey })
 * const check = await pqauth.mandate.verify(mandate.token, 'send_reply', 1, { agentSignature })
 */
export async function signAgentCall(options: SignAgentCallOptions): Promise<PQToken> {
  const { mandate, secretKey } = options
  const lifetime  = options.expiresInSeconds ?? DEFAULT_AGENT_SIGNATURE_LIFETIME_SECONDS

  let mandateId: unknown = mandate
  if (typeof mandate === 'object' && mandate !== null) {
    try {
      mandateId = (JSON.parse(decodePayloadJson(mandate.payload)) as { sub?: unknown }).sub
    } catch {
      throw new PQAuthError('"mandate" is not a valid Mandate token', 'INVALID_ARGUMENT')
    }
  }
  if (typeof mandateId !== 'string' || mandateId.trim() === '') {
    throw new PQAuthError('"mandate" must be the mandate id or the mandate token', 'INVALID_ARGUMENT')
  }
  if (typeof options.action !== 'string' || options.action.trim() === '') {
    throw new PQAuthError('"action" must be a non-empty string', 'INVALID_ARGUMENT')
  }
  if (!Number.isInteger(options.cost) || options.cost < 0) {
    throw new PQAuthError('"cost" must be a non-negative integer', 'INVALID_ARGUMENT')
  }
  if (!Number.isInteger(lifetime) || lifetime < 1) {
    throw new PQAuthError('"expiresInSeconds" must be a positive integer', 'INVALID_ARGUMENT')
  }
  if (typeof secretKey !== 'string' || secretKey === '') {
    throw new PQAuthError('"secretKey" is required', 'INVALID_ARGUMENT')
  }

  if (options.algorithm !== undefined) getMlDsa(options.algorithm)   // an unknown name fails with UNSUPPORTED_ALGORITHM
  const now     = Math.floor(Date.now() / 1000)
  const payload = encodePayloadJson(JSON.stringify({
    sub:    mandateId.trim(),
    action: options.action.trim(),
    cost:   options.cost,
    iat:    now,
    exp:    now + lifetime,
  }))

  let secret: Uint8Array | undefined
  try {
    try {
      secret = fromBase64(secretKey)
    } catch {
      throw new PQAuthError('"secretKey" is not valid base64', 'INVALID_SECRET_KEY')
    }
    // The size of an ML-DSA private key tells its variant (2560, 4032 or 4896 bytes).
    const detected = AGENT_SECRET_KEY_VARIANT[secret.length]
    if (detected === undefined) {
      throw new PQAuthError(
        `"secretKey" is not an ML-DSA private key (${secret.length} bytes; expected 2560, 4032 or 4896). ` +
        'Use the secretKey returned by generateAgentKeyPair(); a 32-byte seed is not accepted',
        'INVALID_SECRET_KEY'
      )
    }
    if (options.algorithm !== undefined && options.algorithm !== detected) {
      throw new PQAuthError(
        `"algorithm" is ${options.algorithm} but the secretKey is an ${detected} key. Omit "algorithm": it is detected from the key`,
        'INVALID_SECRET_KEY'
      )
    }
    const signature = getMlDsa(detected).sign(new TextEncoder().encode(payload), secret)
    return { payload, signature: toBase64(signature), algorithm: detected, issuedAt: now }
  } catch (err) {
    if (err instanceof PQAuthError) throw err
    throw new PQAuthError('"secretKey" is not a valid ML-DSA private key', 'INVALID_SECRET_KEY')
  } finally {
    secret?.fill(0)
  }
}

// ─── PQAuth client ────────────────────────────────────────────────────────────

interface CachedKey {
  publicKey:  string
  fetchedAt:  number
  ttlSeconds: number
}

export class PQAuth {
  private readonly apiKey:      string
  private readonly baseUrl:     string
  private readonly timeout:     number
  private readonly localVerify: boolean
  private readonly projectId?:  string  // ← NUEVO
  private cachedKey:            CachedKey | null = null
  private readonly keyTTL =     3600

  constructor(options: PQAuthOptions | string) {
    if (typeof options === 'string') {
      this.apiKey      = options
      this.baseUrl     = 'https://api.fipsign.dev'
      this.timeout     = 10_000
      this.localVerify = false
      this.projectId   = undefined
    } else {
      this.apiKey      = options.apiKey
      this.baseUrl     = options.baseUrl     ?? 'https://api.fipsign.dev'
      this.timeout     = options.timeout     ?? 10_000
      this.localVerify = options.localVerify ?? false
      this.projectId   = options.projectId
    }
    
    if (this.localVerify && !this.projectId) {
      throw new PQAuthError(
        'projectId is required when localVerify is true — get it from the dashboard or the meta.projectId field of /sign response',
        'MISSING_PROJECT_ID'
      )
    }
    if (!/^pqa_[0-9a-f]{64}$/.test(this.apiKey ?? '')) {
      throw new PQAuthError(
        'Invalid API key format — expected "pqa_" followed by 64 hex characters. Get one at https://app.fipsign.dev',
        'INVALID_API_KEY'
      )
    }
  }

  // ── Private: fetch wrapper ──────────────────────────────────────────────────

  // One call to the API. Resolves with whatever the server answered, whatever the status. Rejects only when
  // no usable answer arrived: PQAuthError TIMEOUT or NETWORK_ERROR (a body that is not JSON counts as that).
  private async send<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<{ ok: boolean; status: number; data: T; retryAfter?: number }> {
    const controller = new AbortController()
    const timer      = setTimeout(() => controller.abort(), this.timeout)

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key':    this.apiKey,
          ...options.headers,
        },
      })

      const data = await res.json() as T
      return {
        ok:         res.ok,
        status:     res.status,
        data,
        retryAfter: parseRetryAfter(res.headers?.get?.('Retry-After')),
      }
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new PQAuthError('Request timed out', 'TIMEOUT')
      }
      throw new PQAuthError(
        `Network error: ${err instanceof Error ? err.message : 'unknown'}`,
        'NETWORK_ERROR'
      )
    } finally {
      clearTimeout(timer)
    }
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const { ok, status, data, retryAfter } =
      await this.send<{ success: boolean; error?: string; code?: unknown } & T>(path, options)

    if (!ok || !data?.success) throw apiError(status, data, retryAfter)

    return data
  }

  // ── Private: public key with cache ──────────────────────────────────────────

  private async getPublicKey(): Promise<string> {
    const now = Math.floor(Date.now() / 1000)

    if (this.cachedKey && (now - this.cachedKey.fetchedAt) < this.cachedKey.ttlSeconds) {
      return this.cachedKey.publicKey
    }

    const controller = new AbortController()
    const timer      = setTimeout(() => controller.abort(), this.timeout)

    try {
      const res  = await fetch(`${this.baseUrl}/public-key`, { signal: controller.signal, headers: { 'X-API-Key': this.apiKey } })
      if (!res.ok) {
        throw new PQAuthError(
          `Failed to fetch public key: ${res.status}`, 'NETWORK_ERROR', res.status,
          { retryAfter: parseRetryAfter(res.headers?.get?.('Retry-After')) }
        )
      }
      const data = await res.json() as { publicKey: string }
      if (!data.publicKey) throw new PQAuthError('Public key response missing publicKey field', 'NETWORK_ERROR')

      this.cachedKey = { publicKey: data.publicKey, fetchedAt: now, ttlSeconds: this.keyTTL }
      return data.publicKey
    } catch (err) {
      if (err instanceof PQAuthError && err.status !== undefined) throw err   // the failed answer above, as it is
      if (err instanceof Error && err.name === 'AbortError') {
        throw new PQAuthError('Public key fetch timed out', 'TIMEOUT')
      }
      throw new PQAuthError(
        `Failed to fetch public key: ${err instanceof Error ? err.message : 'unknown'}`,
        'NETWORK_ERROR'
      )
    } finally {
      clearTimeout(timer)
    }
  }

  // ── sign() ──────────────────────────────────────────────────────────────────

  /**
   * Sign any payload with ML-DSA-65.
   *
   * The only required field is `sub` — any string identifying the entity:
   * a user, an order, a document, a device, an event, anything.
   * All other fields are stored in the payload and returned on verify.
   *
   * Each call counts against your monthly token quota.
   *
   * @example
   * const { token } = await pqauth.sign({ sub: 'user_123', role: 'admin' })
   * const { token } = await pqauth.sign({ sub: 'order_456', amount: 299.99 })
   * const { token } = await pqauth.sign({ sub: 'doc_789', hash: 'sha256:abc...' })
   */
  async sign(options: SignOptions): Promise<SignResult> {
    if (!options.sub) throw new PQAuthError('"sub" is required', 'MISSING_SUB')
    return this.request<SignResult>('/sign', { method: 'POST', body: JSON.stringify(options) })
  }

  // ── verify() ────────────────────────────────────────────────────────────────

  /**
   * Verify a PQAuth token.
   *
   * Never throws — returns { valid: false, error, failure } on failure.
   *
   * `failure` tells a token that was refused ('rejected') from a check that could not be done
   * ('rate_limited', 'quota_exhausted', 'unavailable'; see VerifyFailure). Decide on `failure`, not on
   * the text of `error`. Only 'rejected' means the token is bad.
   *
   * If localVerify: true, verification happens entirely in memory (~1ms, no API call).
   * Local verification does not check the revocation list — use remote verification
   * for sensitive operations such as payments or admin actions.
   *
   * A Mandate token is never a valid session token: verify() rejects it in both modes.
   * Use mandate.verify() for those.
   *
   * @example
   * const { valid, payload, failure, retryAfter } = await pqauth.verify(token)
   * if (!valid && failure === 'rejected') return res.status(401).json({ error: 'Unauthorized' })
   * if (!valid) return res.status(503).set('Retry-After', String(retryAfter ?? 5)).json({ error: 'Try again' })
   */
  async verify(token: PQToken): Promise<VerifyResult> {
    return this.localVerify ? this.verifyLocal(token) : this.verifyRemote(token)
  }

  private async verifyRemote(token: PQToken): Promise<VerifyResult> {
    try {
      const { ok, status, data, retryAfter } = await this.send<{
        success?: boolean; valid?: boolean; error?: string; code?: unknown; payload?: TokenPayload
      } | null>('/verify', {
        method: 'POST',
        body:   JSON.stringify({ token }),
      })
      if (ok && data?.success) return { valid: true, payload: data.payload as TokenPayload, local: false }
      return {
        valid:   false,
        payload: null,
        error:   data?.error ?? `Request failed with status ${status}`,
        local:   false,
        ...classifyVerifyFailure(status, data, retryAfter),
      }
    } catch (err) {
      // No answer arrived (timeout, network, a body that is not JSON): the token was not checked.
      const message = err instanceof PQAuthError ? err.message : 'Unknown error'
      return { valid: false, payload: null, error: message, local: false, failure: 'unavailable' }
    }
  }

private async verifyLocal(token: PQToken): Promise<VerifyResult> {
  try {
    const publicKey = await this.getPublicKey()
    const payload   = verifyLocally(token, publicKey, this.projectId!)
    return { valid: true, payload, local: true }
  } catch (err) {
    if (err instanceof PQAuthError && err.code === 'INVALID_SIGNATURE') {
      // Key may have rotated — clear cache and retry once
      this.cachedKey = null
      try {
        const publicKey = await this.getPublicKey()
        const payload   = verifyLocally(token, publicKey, this.projectId!)
        return { valid: true, payload, local: true }
      } catch (retryErr) {
        // The key could not be refreshed, so it is not known whether the token is bad: say that, not "invalid".
        if (isNoAnswer(retryErr)) return noAnswerResult(retryErr)
        /* Still invalid after key refresh — genuinely bad token */
      }
    }
    // The public key could not be fetched: nothing was checked.
    if (isNoAnswer(err)) return noAnswerResult(err)
    // All other errors reach here: INVALID_SIGNATURE (post-retry), TOKEN_EXPIRED, ISSUER_MISMATCH, etc.
    const message = err instanceof PQAuthError ? err.message : 'Unknown error'
    return { valid: false, payload: null, error: message, local: true, failure: 'rejected' }
  }
}

  // ── revoke() ────────────────────────────────────────────────────────────────

  /**
   * Revoke a token immediately.
   *
   * Future verify() calls will reject it even if the signature is valid
   * and the token has not yet expired.
   *
   * @example
   * await pqauth.revoke(token, 'user logged out')
   */
  async revoke(token: PQToken, reason?: string): Promise<RevokeResult> {
    return this.request<RevokeResult>('/revoke', {
      method: 'POST',
      body:   JSON.stringify({ token, reason }),
    })
  }

  // ── usage() ─────────────────────────────────────────────────────────────────

  /**
   * Get current token balance and 6-month usage history.
   */
  async usage(): Promise<UsageResult> {
    return this.request<UsageResult>('/usage')
  }

  // ── ca ───────────────────────────────────────────────────────────────────────

  /**
   * Certificate Authority — issue and verify post-quantum certificates.
   *
   * The CA root is created once per project from the dashboard.
   * Use ca.issue() to certify devices, services, or any entity at scale.
   * Use ca.verifyCert() to verify certificates entirely offline — no API call needed.
   *
   * @example — issue a certificate for a device
   * const { certificate } = await pqauth.ca.issue({
   *   subject:          'device-serial-00123',
   *   publicKey:        devicePublicKeyB64,
   *   expiresInSeconds: 365 * 24 * 60 * 60,
   *   meta:             { model: 'lock-v2', batch: '2026-05' },
   * })
   *
   * @example — verify a certificate offline
   * const result = pqauth.ca.verifyCert(deviceCert, rootCert)
   * if (!result.valid) return reject(result.error)
   *
   * @example — check revocation (and that the list was signed by the CA)
   * const list  = await pqauth.ca.getCrl()
   * const check = await pqauth.ca.verifyCrl(list, rootCert)
   * if (!check.valid) return reject(check.error)
   * const revoked = pqauth.ca.isCertRevoked(deviceCert, list.crl)
   */
  readonly ca = {

    /**
     * Issue a certificate signed by this project's CA.
     * Costs 1 token per call.
     */
    issue: (options: CaIssueCertOptions): Promise<CaIssueCertResult> =>
      this.request<CaIssueCertResult>('/ca/issue', {
        method: 'POST',
        body:   JSON.stringify(options),
      }),

    /**
     * Revoke a certificate immediately.
     * Costs 1 token per call.
     */
    revokeCert: (certId: string, reason?: string): Promise<CaRevokeCertResult> =>
      this.request<CaRevokeCertResult>('/ca/revoke', {
        method: 'POST',
        body:   JSON.stringify({ certId, reason }),
      }),

    /**
     * Get a certificate by ID.
     * Free — no token cost.
     */
    getCert: (certId: string): Promise<CaGetCertResult> =>
      this.request<CaGetCertResult>(`/ca/certificate/${encodeURIComponent(certId)}`),

    /**
     * Get the Certificate Revocation List for this project's CA.
     * Free — no token cost.
     *
     * The list is signed by the CA (PQCert and X.509): `crl` has the entries and `raw` the whole signed object.
     * Check the signature with ca.verifyCrl() before you trust the list.
     */
getCrl: async (): Promise<CaGetCrlResult> => {
  const data = await this.request<Record<string, unknown>>('/ca/crl')
  const rawCrl = data.crl

  // The answer carries `crl` as the signed object {caId, subject, format, algorithm, generatedAt, revokedCerts, signature}:
  // `crl` below is its revokedCerts, and `raw` keeps the whole object for ca.verifyCrl().
  if (rawCrl && !Array.isArray(rawCrl) && typeof rawCrl === 'object') {
    const obj = rawCrl as Record<string, unknown>
    return {
      caId:        (obj.caId        ?? data.caId        ?? '') as string,
      subject:     (obj.subject     ?? data.subject     ?? '') as string,
      crl:         (obj.revokedCerts ?? []) as CrlEntry[],
      generatedAt: (obj.generatedAt  ?? data.generatedAt ?? 0) as number,
      raw:         obj,
    }
  }

  // A plain array of entries (no signature): there is no `raw`, and ca.verifyCrl() says the list is not signed.
  return {
    caId:        (data.caId        as string) ?? '',
    subject:     (data.subject     as string) ?? '',
    crl:         (data.crl         ?? []) as CrlEntry[],
    generatedAt: (data.generatedAt as number) ?? 0,  // 0 = backend no retornó el campo (no debería ocurrir)
  }
},

    /**
     * Verify a certificate entirely offline using the CA root certificate.
     * No API call — uses ML-DSA-65 locally.
     * Does NOT check revocation — call getCrl() and isCertRevoked() for that.
     */
    verifyCert: (cert: PQCert, rootCert: PQCert): VerifyCertResult => {
      try {
        verifyCertLocally(cert, rootCert)
        return { valid: true, cert }
      } catch (err) {
        const message = err instanceof PQAuthError ? err.message : 'Unknown error'
        return { valid: false, error: message }
      }
    },

    /**
     * Check if a certificate appears in a CRL.
     * Offline — pass the result of getCrl().
     *
     * Accepts either a PQCert object (pqcert format) or a certId string (x509 format).
     * The certId string is returned in the `meta.certId` field of ca.issue().
     *
     * @example — PQCert format
     * const revoked = pqauth.ca.isCertRevoked(cert, crl)
     *
     * @example — X.509 format
     * const revoked = pqauth.ca.isCertRevoked(meta.certId, crl)
     */
    isCertRevoked: (certOrId: PQCert | string, crl: CrlEntry[]): boolean => {
      const id = typeof certOrId === 'string' ? certOrId : certOrId.id
      return crl.some(entry => entry.certId === id)
    },

    /**
     * Check that a revocation list was signed by this CA. Offline: no API call, ML-DSA-65 locally.
     *
     * Pass the result of ca.getCrl() (or the signed `crl` object of the REST answer) and the root certificate of the CA:
     * the CA_ROOT object of a PQCert CA, or the PEM string of an X.509 CA. When `valid` is true, the list is exactly what
     * the CA signed at `generatedAt`: nobody hid, added or changed a revocation, and it is not a list of another CA.
     * When you pass the result of ca.getCrl(), it also has to be the signed list (what you read from `crl` is what was signed).
     *
     * The signature covers `generatedAt`, so an old list cannot pass as a new one, but an old list that was signed is
     * still valid: decide how old a list you accept (`Date.now() / 1000 - result.generatedAt`).
     * It does not check the expiry of the root: ca.verifyCert() and ca.verifyX509Cert() do that for certificates.
     *
     * Never throws — returns { valid: false, error } on any failure.
     *
     * @example
     * const list  = await pqauth.ca.getCrl()
     * const check = await pqauth.ca.verifyCrl(list, rootCert)
     * if (!check.valid) return reject(check.error)
     * const revoked = pqauth.ca.isCertRevoked(deviceCert, list.crl)
     */
    verifyCrl: async (crl: CaGetCrlResult | SignedCrl, root: PQCert | string): Promise<VerifyCrlResult> => {
      try {
        return { valid: true, generatedAt: await verifyCrlLocally(crl, root) }
      } catch (err) {
        return { valid: false, error: err instanceof Error ? err.message : 'Unknown error' }
      }
    },

    /**
     * Verify an X.509 ML-DSA-65 certificate entirely offline.
     * No API call — parses the PEM locally and verifies the ML-DSA-65 signature.
     *
     * Only for X.509 format CAs. For PQCert format use ca.verifyCert() instead.
     * Does NOT check revocation — call getCrl() and isCertRevoked() for that.
     *
     * Never throws — returns { valid: false, error } on any failure.
     *
     * @example
     * const result = await pqauth.ca.verifyX509Cert(deviceCertPem, rootCertPem)
     * if (!result.valid) return reject(result.error)
     */
    verifyX509Cert: async (certPem: string, rootPem: string): Promise<VerifyCertResult> => {
      try {
        const { AsnConvert }  = await import('@peculiar/asn1-schema')
        const { Certificate } = await import('@peculiar/asn1-x509')

        // ── Parsear ambos certs desde PEM ───────────────────────────────────
        const pemToDer = (pem: string): Uint8Array => {
          const b64    = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')
          const binary = atob(b64)
          const bytes  = new Uint8Array(binary.length)
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
          return bytes
        }

        const certDer = pemToDer(certPem)
        const rootDer = pemToDer(rootPem)

        const cert = AsnConvert.parse(
          certDer.buffer.slice(certDer.byteOffset, certDer.byteOffset + certDer.byteLength),
          Certificate
        )
        const root = AsnConvert.parse(
          rootDer.buffer.slice(rootDer.byteOffset, rootDer.byteOffset + rootDer.byteLength),
          Certificate
        )

        // ── Verificar expiración del leaf ──────────────────────────────────
        const now      = new Date()
        const notAfter = cert.tbsCertificate.validity.notAfter.utcTime
          ?? cert.tbsCertificate.validity.notAfter.generalTime
        if (notAfter && notAfter < now) {
          return { valid: false, error: 'Certificate has expired' }
        }

        // ── Verificar vigencia del root CA ──────────────────────────────────
        const rootNotAfter = root.tbsCertificate.validity.notAfter.utcTime
          ?? root.tbsCertificate.validity.notAfter.generalTime
        if (rootNotAfter && rootNotAfter < now) {
          return { valid: false, error: 'Root CA certificate has expired' }
        }

        // ── Verificar algoritmo de firma ────────────────────────────────────────
        const OID_ML_DSA_65 = '2.16.840.1.101.3.4.3.18'

        const certAlg = cert.signatureAlgorithm.algorithm
        if (certAlg !== OID_ML_DSA_65) {
          return {
            valid: false,
            error: `Unsupported signature algorithm: ${certAlg}. Expected ML-DSA-65 (${OID_ML_DSA_65})`,
          }
        }

        const rootAlg = root.signatureAlgorithm.algorithm
        if (rootAlg !== OID_ML_DSA_65) {
          return {
            valid: false,
            error: `Unsupported root CA algorithm: ${rootAlg}. Expected ML-DSA-65 (${OID_ML_DSA_65})`,
          }
        }

        // ── Extraer public key del root cert ────────────────────────────────────
        // subjectPublicKeyInfo.subjectPublicKey es un ArrayBuffer del BIT STRING content.
        // Dependiendo de la versión de @peculiar/asn1-x509, puede incluir o no
        // el byte 0x00 de unused-bits al inicio. ML-DSA-65 public key = 1952 bytes raw.
        // Estrategia robusta: probar con y sin el primer byte.
        const spkiRaw = new Uint8Array(root.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey)
        let publicKey: Uint8Array
        if (spkiRaw.length === 1952) {
          publicKey = spkiRaw                // ya son los bytes raw
        } else if (spkiRaw.length === 1953 && spkiRaw[0] === 0x00) {
          publicKey = spkiRaw.slice(1)       // skip unused-bits byte
        } else {
          return {
            valid: false,
            error: `Unexpected public key size: ${spkiRaw.length} bytes (expected 1952 or 1953 for ML-DSA-65)`,
          }
        }

        // ── Extraer TBS y firma del device cert ─────────────────────────────
        // El mensaje a verificar es la serialización DER del TBSCertificate.
        const tbsDer = new Uint8Array(AsnConvert.serialize(cert.tbsCertificate))
        // signatureValue: mismo tratamiento robusto para unused-bits byte
        const sigRaw = new Uint8Array(cert.signatureValue)
        let signature: Uint8Array
        if (sigRaw.length === 3309) {
          signature = sigRaw                 // ya son los bytes raw
        } else if (sigRaw.length === 3310 && sigRaw[0] === 0x00) {
          signature = sigRaw.slice(1)        // skip unused-bits byte
        } else {
          return {
            valid: false,
            error: `Unexpected signature size: ${sigRaw.length} bytes (expected 3309 or 3310 for ML-DSA-65)`,
          }
        }

        // ── Verificar firma ML-DSA-65 ───────────────────────────────────────
        // OID ML-DSA-65: 2.16.840.1.101.3.4.3.18 (RFC 9881 final)
        const valid = ml_dsa65.verify(signature, tbsDer, publicKey)

        return valid
          ? { valid: true, cert: certPem }
          : { valid: false, error: 'Invalid certificate signature — not signed by this root CA' }

      } catch (err) {
        return {
          valid: false,
          error: err instanceof Error ? err.message : 'Unknown error during X.509 verification',
        }
      }
    },
  }

  // ── mandate ──────────────────────────────────────────────────────────────────

  /**
   * Mandate — bounded, revocable authorization for AI agents and automated
   * services. A mandate defines what an agent can do (scope), for how long,
   * and under what usage limit (budget) — signed with ML-DSA so the agent
   * can carry proof of its own authorization.
   *
   * REST-only on the backend today — this namespace is a thin typed wrapper
   * over POST/PATCH/GET /mandate, same shape as `ca` above.
   *
   * @example — emit a mandate for an agent
   * const { mandate } = await pqauth.mandate.emit({
   *   agentId:          'agent_support_bot',
   *   issuedBy:         'user_42',
   *   scope:            ['read_tickets', 'send_reply'],
   *   budgetTotal:      100,
   *   expiresInSeconds: 3600,
   * })
   *
   * @example — check authorization before the agent acts
   * const check = await pqauth.mandate.verify(mandate.token, 'send_reply', 1)
   * if (check.result !== 'granted') return reject(check.reason)
   *
   * @example — narrow, suspend, resume, revoke
   * await pqauth.mandate.narrow(mandate.id, ['read_tickets'])
   * await pqauth.mandate.suspend(mandate.id)
   * await pqauth.mandate.resume(mandate.id)
   * await pqauth.mandate.revoke(mandate.id)
   */
  readonly mandate = {

    /**
     * Emit a new mandate. Billed at the platform price of POST /mandate (see the pricing table
     * in the guide).
     *
     * `budgetTotal: 0` means unlimited budget — the rejection check is
     * skipped, but budgetConsumed still accumulates (budgetRemaining stays 0).
     *
     * Pass `agentPublicKey` to require proof of possession: the mandate token stops being a
     * pure bearer credential, and every verify() must carry an `agentSignature` made with the
     * agent's private key. The agent keeps the private key; only the public key reaches FIPSign.
     *
     * @example — mandate with proof of possession
     * // where the agent lives (keep secretKey there). Pass { algorithm: 'ML-DSA-44' | 'ML-DSA-87' } to choose the variant:
     * const { publicKey, secretKey } = await generateAgentKeyPair()
     * // where you emit the mandate:
     * const { mandate } = await pqauth.mandate.emit({ ..., agentPublicKey: publicKey })
     * // each time the agent acts (agent side, no API key needed):
     * const agentSignature = await signAgentCall({ mandate: mandate.token, action: 'send_reply', cost: 1, secretKey })
     * // each time the service checks it:
     * const check = await pqauth.mandate.verify(mandate.token, 'send_reply', 1, { agentSignature })
     */
    emit: (options: MandateEmitOptions): Promise<MandateEmitResult> =>
      this.request<MandateEmitResult>('/mandate', {
        method: 'POST',
        body:   JSON.stringify(options),
      }),

    /**
     * Verify a mandate token and check whether `action` is authorized
     * right now — signature, expiry, status, scope, and remaining budget,
     * all in one atomic server-side check.
     *
     * Never throws — returns { result: 'denied', reason, failure } on any failure
     * (invalid signature, expired, suspended, revoked, action not in
     * scope, budget exhausted, a missing/invalid agent signature, or a call that got no
     * usable answer). Billed (at the platform price of POST /mandate/verify) only when the
     * result is 'granted' — a denial from FIPSign is always free. `reason` is one of
     * MandateDenyReason, or the real error message for failures that never reach the mandate
     * checks (invalid API key, rate limit, network).
     *
     * `failure` tells a denial FIPSign decided ('rejected', 'rate_limited', 'quota_exhausted',
     * 'unavailable': nothing was consumed, repeating the call is safe) from
     * 'outcome_unknown' (timeout, network, server error: the call MAY have been granted and
     * charged; see MandateVerifyFailure for what to do). Decide on `failure`, not on `reason`.
     * The SDK never repeats a call by itself: FIPSign does not recognise a repeated request.
     *
     * If the mandate was emitted with `agentPublicKey`, pass the agent's signature (made with
     * signAgentCall) in `options.agentSignature`. It covers this exact mandate, action and
     * cost, expires within seconds and can be used once: make a new one for every call.
     *
     * Unlike pqauth.verify(), there is no local/offline mode here: budget
     * and scope are live mutable state that can only be checked against
     * the server, not the signature alone.
     *
     * @example
     * const check = await pqauth.mandate.verify(token, 'send_email', 1)
     * if (check.result !== 'granted') return reject(check.reason)
     */
    verify: async (token: PQToken, action: string, cost: number, options?: MandateVerifyOptions): Promise<MandateVerifyResult> => {
      const controller = new AbortController()
      const timer      = setTimeout(() => controller.abort(), this.timeout)
      // Set as soon as FIPSign's answer starts to arrive: the status alone tells whether the call could have been
      // applied, even when the body that follows cannot be read.
      let status:     number | undefined
      let retryAfter: number | undefined
      try {
        const res = await fetch(`${this.baseUrl}/mandate/verify`, {
          method:  'POST',
          signal:  controller.signal,
          headers: { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
          body:    JSON.stringify({ token, action, cost, ...(options?.agentSignature ? { agentSignature: options.agentSignature } : {}) }),
        })
        status     = res.status
        retryAfter = parseRetryAfter(res.headers?.get?.('Retry-After'))
        // Deliberately NOT using this.request() here: a 'denied' result is
        // a normal, expected outcome carrying real data (reason,
        // authorizedScope, budgetConsumedUnits, budgetTotalUnits) in a
        // 403 response — not an error to discard. request() only forwards
        // a generic `error` field on failure, which this endpoint doesn't
        // use, so those fields would be lost if we let it throw.
        const data = await res.json() as (MandateVerifyResult & { success?: boolean; error?: string; code?: unknown }) | null
        if (data?.result === 'granted') return data
        if (data?.result === 'denied')  return { ...data, failure: 'rejected' }
        // Failures that never reach mandate-specific logic (invalid/missing
        // API key, rate limit, malformed body) come back through the
        // generic errorResponse() shape — { success:false, error } — with
        // no `result` field at all. Normalize those into the same denied
        // shape instead of silently dropping the real error message.
        return {
          result: 'denied',
          reason: data?.error ?? `Request failed with status ${res.status}`,
          ...classifyMandateVerifyFailure(res.status, data, retryAfter),
        }
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          // No usable answer: the call may have been applied.
          return { result: 'denied', reason: 'Request timed out', failure: 'outcome_unknown' }
        }
        // `status` is set only when an answer did start to arrive (its body was not JSON, or broke off): its status
        // still tells whether the call could have been applied. Without it, no answer arrived at all.
        return {
          result: 'denied',
          reason: err instanceof SyntaxError && status !== undefined
            ? `Request failed with status ${status}`
            : `Network error: ${err instanceof Error ? err.message : 'unknown'}`,
          ...(status === undefined ? { failure: 'outcome_unknown' as const } : classifyMandateVerifyFailure(status, null, retryAfter)),
        }
      } finally {
        clearTimeout(timer)
      }
    },

    /**
     * Permanently shrink a mandate's scope to a subset of its current
     * scope. Monotonic — cannot be reversed, and cannot re-widen toward
     * the original scope. To restore scope, emit a new mandate.
     */
    narrow: (mandateId: string, scope: string[]): Promise<MandatePatchResult> =>
      this.request<MandatePatchResult>(`/mandate/${encodeURIComponent(mandateId)}`, {
        method: 'PATCH',
        body:   JSON.stringify({ action: 'narrow', scope }),
      }),

    /** Temporarily pause a mandate. verify() will deny while suspended. */
    suspend: (mandateId: string): Promise<MandatePatchResult> =>
      this.request<MandatePatchResult>(`/mandate/${encodeURIComponent(mandateId)}`, {
        method: 'PATCH',
        body:   JSON.stringify({ action: 'suspend' }),
      }),

    /** Reactivate a suspended mandate. */
    resume: (mandateId: string): Promise<MandatePatchResult> =>
      this.request<MandatePatchResult>(`/mandate/${encodeURIComponent(mandateId)}`, {
        method: 'PATCH',
        body:   JSON.stringify({ action: 'resume' }),
      }),

    /** Permanently terminate a mandate. Irreversible. */
    revoke: (mandateId: string): Promise<MandatePatchResult> =>
      this.request<MandatePatchResult>(`/mandate/${encodeURIComponent(mandateId)}`, {
        method: 'PATCH',
        body:   JSON.stringify({ action: 'revoke' }),
      }),

    /** Get a mandate's current state by id. Free — no token cost. */
    get: (mandateId: string): Promise<MandateGetResult> =>
      this.request<MandateGetResult>(`/mandate/${encodeURIComponent(mandateId)}`),

    /**
     * List one page of this project's mandates, newest first. Free — no token cost.
     *
     * A page can hold fewer than `limit` mandates (even none) while `nextCursor` is not null:
     * keep following `nextCursor` until it is null, or use listAll().
     */
    list: (options?: MandateListOptions): Promise<MandateListResult> => {
      const params = new URLSearchParams()
      if (options?.limit  !== undefined) params.set('limit',  String(options.limit))
      if (options?.cursor !== undefined) params.set('cursor', options.cursor)
      const query = params.toString()
      return this.request<MandateListResult>(query ? `/mandate?${query}` : '/mandate')
    },

    /**
     * Iterate over every mandate of this project, newest first, following nextCursor page by page.
     * Free — no token cost. Stop early with `break`: no further page is requested.
     *
     * @example
     * for await (const m of pqauth.mandate.listAll()) console.log(m.id, m.status)
     */
    listAll: (options?: { limit?: number }): AsyncGenerator<Mandate, void, undefined> =>
      this.iterateMandates(options?.limit),
  }

  // Follows nextCursor until it is null. A page can be short or empty while more pages exist, so the
  // loop is driven by the cursor, never by the page size.
  private async *iterateMandates(limit?: number): AsyncGenerator<Mandate, void, undefined> {
    let cursor: string | undefined
    for (;;) {
      const page = await this.mandate.list({
        ...(limit  !== undefined ? { limit }  : {}),
        ...(cursor !== undefined ? { cursor } : {}),
      })
      for (const m of page.mandates) yield m
      if (page.nextCursor === null) return
      if (page.nextCursor === cursor) {
        throw new PQAuthError('Pagination cursor did not advance', 'API_ERROR')
      }
      cursor = page.nextCursor
    }
  }

  // ── zes ──────────────────────────────────────────────────────────────────────

  /**
   * Zero-Exposure Signing — hash sensitive data locally and sign only the
   * hash. The original data never reaches the API.
   *
   * Uses the standard sign()/verify() under the hood — this is a convenience
   * wrapper, not a different endpoint. Revocation and everything else work
   * exactly like any other token: use pqauth.revoke(token) directly, there
   * is no zes.revoke().
   *
   * @example — sign
   * const { token, hash } = await pqauth.zes.sign({ patient: 'Jane Doe', diagnosis: 'confidential' })
   *
   * @example — verify
   * const { valid, dataMatches } = await pqauth.zes.verify(token, originalData)
   * if (!valid || !dataMatches) return reject('invalid or tampered')
   */
  readonly zes = {

    /**
     * Hashes `data` locally with SHA-256 (keys sorted recursively for a
     * deterministic hash regardless of key order) and signs only the hash.
     * Costs 1 token, same as a regular sign() call.
     */
    sign: async (data: unknown, options?: { expiresInSeconds?: number }): Promise<SignResult & { hash: string }> => {
      const hash   = await sha256Hex(canonicalizeForSigning(data))
      const result = await this.sign({
        sub: 'zes:' + hash,
        zes: true,
        ...(options?.expiresInSeconds !== undefined ? { expiresInSeconds: options.expiresInSeconds } : {}),
      })
      return { ...result, hash }
    },

    /**
     * Re-hashes `data` locally and verifies the token, confirming the hash
     * inside the token matches `data`. `data` is never sent to the API.
     */
    verify: async (token: PQToken, data: unknown): Promise<VerifyResult & { dataMatches: boolean }> => {
      const hash        = await sha256Hex(canonicalizeForSigning(data))
      const result      = await this.verify(token)
      const dataMatches = result.valid && result.payload?.sub === 'zes:' + hash
      return { ...result, dataMatches }
    },
  }

  // ── middleware() ─────────────────────────────────────────────────────────────

  /**
   * Express / Fastify middleware. Node.js only.
   *
   * Answers 401 only when the token is refused (`failure: 'rejected'`), or when the Authorization
   * header is missing or not a token. When FIPSign could not check the token (rate limit, quota,
   * timeout, network, server error, invalid API key) it answers 503 with
   * `{ error: 'Authentication service temporarily unavailable' }`, plus a `Retry-After` header
   * when the wait is known, so the user is not logged out for something that is not their fault.
   * To log the real cause, call verify() yourself and read `error` and `failure`.
   *
   * @example
   * app.use('/api', pqauth.middleware())
   */
  middleware() {
    return async (
      req: MiddlewareRequest & { user?: TokenPayload },
      res: MiddlewareResponse,
      next: NextFunction
    ) => {
      const authHeader  = req.headers['authorization']
      const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader

      if (!headerValue?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header required (Bearer <token>)' })
      }

      let token: PQToken
      try {
        const b64     = headerValue.slice(7)
        const decoded = atob(b64)
        token = JSON.parse(decoded)
      } catch {
        return res.status(401).json({ error: 'Invalid token format' })
      }

      const result = await this.verify(token)
      if (!result.valid) {
        if (result.failure === undefined || result.failure === 'rejected') {
          return res.status(401).json({ error: result.error ?? 'Invalid token' })
        }
        // FIPSign could not check the token: it is not to blame, so not a 401 (the app would log the user out).
        if (result.retryAfter !== undefined) res.setHeader?.('Retry-After', String(result.retryAfter))
        return res.status(503).json({ error: 'Authentication service temporarily unavailable' })
      }

      req.user = result.payload!
      next()
    }
  }

  // ── preloadPublicKey() ───────────────────────────────────────────────────────

  /**
   * Preload and cache the server's public key at startup.
   *
   * @example
   * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true, projectId: 'proj_...' })
   * await pqauth.preloadPublicKey()
   */
  async preloadPublicKey(): Promise<void> {
    await this.getPublicKey()
  }

  // ── health() ─────────────────────────────────────────────────────────────────

  /**
   * Check the health of the PQAuth service.
   */
async health(): Promise<HealthResult> {
  const controller = new AbortController()
  const timer      = setTimeout(() => controller.abort(), this.timeout)
  try {
    const res  = await fetch(`${this.baseUrl}/health`, { signal: controller.signal })
    const data = await res.json() as HealthResult
    if (!res.ok) throw new PQAuthError(`Health check failed: ${res.status}`, 'API_ERROR', res.status)
    return data
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new PQAuthError('Request timed out', 'TIMEOUT')
    }
    throw new PQAuthError(
      `Network error: ${err instanceof Error ? err.message : 'unknown'}`,
      'NETWORK_ERROR'
    )
  } finally {
    clearTimeout(timer)
  }
}
}

export default PQAuth