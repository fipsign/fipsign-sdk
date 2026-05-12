/**
 * pqauth-sdk v0.4.0
 *
 * Post-quantum authentication SDK for Node.js and the browser.
 * Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.
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
  email?:            string
  role?:             string
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
  }
  usage: {
    count:     number
    limit:     number
    remaining: number
    month:     string
  }
}

export interface VerifyResult {
  valid:   boolean
  payload: TokenPayload | null
  error?:  string
  local?:  boolean
}

export interface TokenPayload {
  sub:    string
  email?: string
  role?:  string
  iat:    number
  exp:    number
  [key: string]: unknown
}

export interface RevokeResult {
  success:   boolean
  message:   string
  revokedAt: number
  sub:       string
}

// Usage is tracked globally per developer account (not per project).
// All projects share a single monthly pool defined by the account plan.
export interface UsageResult {
  current: {
    count:     number
    month:     string
    limit:     number
    remaining: number
    plan:      string
  }
  history:   { month: string; count: number }[]
  developer: { email: string; plan: string }
  note:      string
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

export interface HealthResult {
  status:           string
  algorithm:        string
  standard:         string
  quantumResistant: boolean
  version:          string
}

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

// ─── Local verification helpers ───────────────────────────────────────────────

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes  = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

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
      this.baseUrl     = 'https://pqauth-core.gdbok.workers.dev'
      this.timeout     = 10_000
      this.localVerify = false
    } else {
      this.apiKey      = options.apiKey
      this.baseUrl     = options.baseUrl     ?? 'https://pqauth-core.gdbok.workers.dev'
      this.timeout     = options.timeout     ?? 10_000
      this.localVerify = options.localVerify ?? false
    }

    if (!this.apiKey?.startsWith('pqa_')) {
      throw new PQAuthError(
        'Invalid API key — keys must start with "pqa_". Get one at https://pqauth-dashboard.pages.dev',
        'INVALID_API_KEY'
      )
    }
  }

  // ── Private: fetch with timeout ─────────────────────────────────────────────

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

  // ── Private: public key fetch with timeout and cache ────────────────────────

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
   * Sign a token for an authenticated user.
   * Call this after verifying your user's credentials.
   *
   * @example
   * const { token } = await pqauth.sign({ sub: user.id, email: user.email })
   */
  async sign(options: SignOptions): Promise<SignResult> {
    if (!options.sub) throw new PQAuthError('"sub" is required', 'MISSING_SUB')
    return this.request<SignResult>('/sign', { method: 'POST', body: JSON.stringify(options) })
  }

  // ── verify() ────────────────────────────────────────────────────────────────

  /**
   * Verify a PQAuth token. Never throws — returns { valid: false, error } on failure.
   *
   * If localVerify: true, verification happens in memory (~1ms, no API call).
   * Note: local verification does not check the revocation list.
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
      // Key mismatch may mean keys were rotated — invalidate cache and retry once
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
   * Future verify() calls will reject it even if the signature is valid.
   * Requires an API call even when localVerify is enabled.
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
   * Get current month usage and 6-month history.
   * Usage is tracked globally per account — all projects share one monthly pool.
   */
  async usage(): Promise<UsageResult> {
    return this.request<UsageResult>('/usage')
  }

  // ── webhooks ────────────────────────────────────────────────────────────────

  readonly webhooks = {
    register: (options: { url: string; events?: WebhookEvent[] }): Promise<WebhookResult> =>
      this.request<WebhookResult>('/webhooks', { method: 'POST', body: JSON.stringify(options) }),

    get: (): Promise<{ webhook: WebhookResult['webhook'] | null }> =>
      this.request('/webhooks'),

    delete: (): Promise<{ success: boolean }> =>
      this.request('/webhooks', { method: 'DELETE' }),

    test: (): Promise<{ success: boolean; message: string }> =>
      this.request('/webhooks/test', { method: 'POST' }),
  }

  // ── middleware() — Node.js only ──────────────────────────────────────────────

  /**
   * Express / Fastify middleware. Node.js only.
   * Reads Authorization: Bearer <base64(token)> and attaches payload to req.user.
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
        // Use atob for browser/edge compatibility; Buffer fallback for older Node
        const b64     = headerValue.slice(7)
        const decoded = typeof atob !== 'undefined'
          ? atob(b64)
          : Buffer.from(b64, 'base64').toString('utf8')
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

  // ── preloadPublicKey() ────────────────────────────────────────────────────────

  /**
   * Preload and cache the server's public key at startup.
   * Recommended when using localVerify: true to avoid first-request latency.
   *
   * @example
   * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
   * await pqauth.preloadPublicKey()
   */
  async preloadPublicKey(): Promise<void> {
    await this.getPublicKey()
  }

  // ── health() ────────────────────────────────────────────────────────────────

  async health(): Promise<HealthResult> {
    const controller = new AbortController()
    const timer      = setTimeout(() => controller.abort(), this.timeout)
    try {
      const res = await fetch(`${this.baseUrl}/health`, { signal: controller.signal })
      return res.json()
    } finally {
      clearTimeout(timer)
    }
  }
}

export default PQAuth
