/**
 * fipsign-sdk v0.6.0
 *
 * Post-quantum signing SDK for Node.js and the browser.
 * Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.
 *
 * Sign anything: users, orders, documents, devices, events.
 * The only required field is `sub` — any string identifying the entity.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PQAuthOptions {
  apiKey:       string
  baseUrl?:     string
  timeout?:     number
  localVerify?: boolean
}

export interface SignOptions {
  sub:               string
  expiresInSeconds?: number
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

export interface VerifyResult {
  valid:   boolean
  payload: TokenPayload | null
  error?:  string
  local?:  boolean
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

export interface WebhookResult {
  webhook: {
    url:    string
    events: WebhookEvent[]
    secret: string
  }
}

export interface WebhookGetResult {
  webhook: {
    url:       string
    events:    WebhookEvent[]
    active?:   boolean  // present in get() response
    createdAt?: number  // Unix timestamp — present in get() response
  } | null
}

export interface HealthResult {
  status:           string
  algorithm:        string
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
  reason:    string | null
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
  raw?:        Record<string, unknown>  // x509 only: full signed CRL object with ML-DSA-65 signature
}

export interface VerifyCertResult {
  valid:  boolean
  cert?:  PQCert | string  // PQCert para pqcert, string PEM para x509
  error?: string
}

// ─── Middleware types ─────────────────────────────────────────────────────────

export interface MiddlewareRequest {
  headers: { [key: string]: string | string[] | undefined }
}

export interface MiddlewareResponse {
  status: (code: number) => MiddlewareResponse
  json:   (data: unknown) => void
}

export type NextFunction = (err?: unknown) => void

// ─── Errors ───────────────────────────────────────────────────────────────────

export class PQAuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status?: number
  ) {
    super(message)
    this.name = 'PQAuthError'
  }
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

// ─── Local token verification ─────────────────────────────────────────────────

function verifyLocally(token: PQToken, publicKeyB64: string): TokenPayload {
  if (token.algorithm !== 'ML-DSA-65') {
    throw new PQAuthError(`Unsupported algorithm: ${token.algorithm}`, 'UNSUPPORTED_ALGORITHM')
  }

  const publicKey = fromBase64(publicKeyB64)
  const signature = fromBase64(token.signature)
  const message   = new TextEncoder().encode(token.payload)

  const isValid = ml_dsa65.verify(signature, message, publicKey)
  if (!isValid) {
    throw new PQAuthError(
      'Invalid signature — token was tampered with or not issued by this server',
      'INVALID_SIGNATURE'
    )
  }

  const payload: TokenPayload = JSON.parse(atob(token.payload))
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp < now) {
    throw new PQAuthError(`Token expired ${now - payload.exp} seconds ago`, 'TOKEN_EXPIRED')
  }

  return payload
}

// ─── Local certificate verification ──────────────────────────────────────────

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
  if (cert.expiresAt !== undefined && cert.expiresAt < now) {
    throw new PQAuthError(
      `Certificate expired ${now - cert.expiresAt} seconds ago`,
      'CERT_EXPIRED'
    )
  }

  const { signature, ...certWithoutSig } = cert
  function sortedKeys(obj: unknown): unknown {
    if (Array.isArray(obj)) return obj.map(sortedKeys)
    if (obj !== null && typeof obj === 'object') {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(obj as Record<string, unknown>).sort()) {
        sorted[k] = sortedKeys((obj as Record<string, unknown>)[k])
      }
      return sorted
    }
    return obj
  }
  const canonical = JSON.stringify(sortedKeys(certWithoutSig))
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

// ─── generateKeyPair ──────────────────────────────────────────────────────────

/**
 * Generate an ML-DSA-65 key pair for a device or entity.
 *
 * The entity keeps the secretKey private and passes the publicKey
 * to pqauth.ca.issue() to obtain a certificate.
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
  private cachedKey:            CachedKey | null = null
  private readonly keyTTL =     3600

  constructor(options: PQAuthOptions | string) {
    if (typeof options === 'string') {
      this.apiKey      = options
      this.baseUrl     = 'https://api.fipsign.dev'
      this.timeout     = 10_000
      this.localVerify = false
    } else {
      this.apiKey      = options.apiKey
      this.baseUrl     = options.baseUrl     ?? 'https://api.fipsign.dev'
      this.timeout     = options.timeout     ?? 10_000
      this.localVerify = options.localVerify ?? false
    }

    if (!/^pqa_[0-9a-f]{64}$/.test(this.apiKey ?? '')) {
      throw new PQAuthError(
        'Invalid API key format — expected "pqa_" followed by 64 hex characters. Get one at https://app.fipsign.dev',
        'INVALID_API_KEY'
      )
    }
  }

  // ── Private: fetch wrapper ──────────────────────────────────────────────────

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
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

      const data = await res.json() as { success: boolean; error?: string } & T

      if (!res.ok || !data.success) {
        throw new PQAuthError(
          data.error ?? `Request failed with status ${res.status}`,
          'API_ERROR',
          res.status
        )
      }

      return data
    } catch (err) {
      if (err instanceof PQAuthError) throw err
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

  // ── Private: public key with cache ──────────────────────────────────────────

  private async getPublicKey(): Promise<string> {
    const now = Math.floor(Date.now() / 1000)

    if (this.cachedKey && (now - this.cachedKey.fetchedAt) < this.cachedKey.ttlSeconds) {
      return this.cachedKey.publicKey
    }

    const controller = new AbortController()
    const timer      = setTimeout(() => controller.abort(), this.timeout)

    try {
      const res  = await fetch(`${this.baseUrl}/public-key`, { signal: controller.signal })
      const data = await res.json() as { publicKey: string }

      this.cachedKey = { publicKey: data.publicKey, fetchedAt: now, ttlSeconds: this.keyTTL }
      return data.publicKey
    } catch (err) {
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
   * Never throws — returns { valid: false, error } on failure.
   *
   * If localVerify: true, verification happens entirely in memory (~1ms, no API call).
   * Local verification does not check the revocation list — use remote verification
   * for sensitive operations such as payments or admin actions.
   *
   * @example
   * const { valid, payload } = await pqauth.verify(token)
   * if (!valid) return res.status(401).json({ error: 'Unauthorized' })
   */
  async verify(token: PQToken): Promise<VerifyResult> {
    return this.localVerify ? this.verifyLocal(token) : this.verifyRemote(token)
  }

  private async verifyRemote(token: PQToken): Promise<VerifyResult> {
    try {
      const data = await this.request<{ payload: TokenPayload }>('/verify', {
        method: 'POST',
        body:   JSON.stringify({ token }),
      })
      return { valid: true, payload: data.payload, local: false }
    } catch (err) {
      const message = err instanceof PQAuthError ? err.message : 'Unknown error'
      return { valid: false, payload: null, error: message, local: false }
    }
  }

  private async verifyLocal(token: PQToken): Promise<VerifyResult> {
    try {
      const publicKey = await this.getPublicKey()
      const payload   = verifyLocally(token, publicKey)
      return { valid: true, payload, local: true }
    } catch (err) {
      if (err instanceof PQAuthError && err.code === 'INVALID_SIGNATURE') {
        this.cachedKey = null
        try {
          const publicKey = await this.getPublicKey()
          const payload   = verifyLocally(token, publicKey)
          return { valid: true, payload, local: true }
        } catch {
          // Still invalid after key refresh — genuinely bad token
        }
      }
      const message = err instanceof PQAuthError ? err.message : 'Unknown error'
      return { valid: false, payload: null, error: message, local: true }
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

  // ── webhooks ────────────────────────────────────────────────────────────────

  /**
   * Manage webhook configuration for real-time event notifications.
   *
   * @example
   * const { webhook } = await pqauth.webhooks.register({
   *   url:    'https://yourapp.com/webhooks/pqauth',
   *   events: ['limit.warning', 'limit.reached', 'token.revoked'],
   * })
   */
  readonly webhooks = {
    register: (options: { url: string; events?: WebhookEvent[] }): Promise<WebhookResult> =>
      this.request<WebhookResult>('/webhooks', { method: 'POST', body: JSON.stringify(options) }),

    get: (): Promise<WebhookGetResult> =>
      this.request('/webhooks'),

    delete: (): Promise<{ success: boolean }> =>
      this.request('/webhooks', { method: 'DELETE' }),

    test: (): Promise<{ success: boolean; message: string }> =>
      this.request('/webhooks/test', { method: 'POST' }),
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
   * @example — check revocation
   * const { crl } = await pqauth.ca.getCrl()
   * const revoked = pqauth.ca.isCertRevoked(deviceCert, crl)
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
      this.request<CaGetCertResult>(`/ca/certificate/${certId}`),

    /**
     * Get the Certificate Revocation List for this project's CA.
     * Free — no token cost.
     */
getCrl: async (): Promise<CaGetCrlResult> => {
  const data = await this.request<Record<string, unknown>>('/ca/crl')
  const rawCrl = data.crl

  // X.509 CA: backend returns crl as a signed object with revokedCerts array
  // PQCert CA: backend returns crl as a flat CrlEntry array
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

  // PQCert — already flat
  return {
    caId:        (data.caId        as string) ?? '',
    subject:     (data.subject     as string) ?? '',
    crl:         (data.crl         ?? []) as CrlEntry[],
    generatedAt: (data.generatedAt as number) ?? 0,
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

        // ── Verificar expiración ────────────────────────────────────────────
        const now      = new Date()
        const notAfter = cert.tbsCertificate.validity.notAfter.utcTime
          ?? cert.tbsCertificate.validity.notAfter.generalTime
        if (notAfter && notAfter < now) {
          return { valid: false, error: 'Certificate has expired' }
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

  // ── middleware() ─────────────────────────────────────────────────────────────

  /**
   * Express / Fastify middleware. Node.js only.
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
        return res.status(401).json({ error: result.error ?? 'Invalid token' })
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
   * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
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
    const res = await fetch(`${this.baseUrl}/health`, { signal: controller.signal })
    return res.json()
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