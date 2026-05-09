/**
 * pqauth-sdk
 *
 * Post-quantum authentication SDK for Node.js and the browser.
 * Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.
 *
 * @example
 * import { PQAuth } from 'pqauth-sdk'
 *
 * const pqauth = new PQAuth('pqa_your_api_key')
 *
 * // Sign a token
 * const { token } = await pqauth.sign({ sub: 'user_123', email: 'user@app.com' })
 *
 * // Verify a token
 * const { valid, payload } = await pqauth.verify(token)
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PQAuthOptions {
  /** Your PQAuth API key (starts with pqa_) */
  apiKey: string
  /** API base URL. Defaults to the PQAuth cloud service. */
  baseUrl?: string
  /** Request timeout in milliseconds. Default: 10000 */
  timeout?: number
}

export interface SignOptions {
  /** Subject — userId or email that identifies the end user */
  sub: string
  /** Optional email of the end user */
  email?: string
  /** Optional role (e.g. 'admin', 'user', 'merchant') */
  role?: string
  /** Token expiry in seconds. Default: 3600 (1 hour) */
  expiresInSeconds?: number
  /** Any additional custom fields */
  [key: string]: unknown
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
  }
}

export interface VerifyResult {
  valid:   boolean
  payload: TokenPayload | null
  error?:  string
}

export interface TokenPayload {
  sub:    string
  email?: string
  role?:  string
  iat:    number
  exp:    number
  [key: string]: unknown
}

export interface HealthResult {
  status:           string
  algorithm:        string
  standard:         string
  quantumResistant: boolean
  version:          string
}

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

// ─── Middleware types ─────────────────────────────────────────────────────────

export interface MiddlewareRequest {
  headers: { [key: string]: string | string[] | undefined }
}

export interface MiddlewareResponse {
  status:  (code: number) => MiddlewareResponse
  json:    (data: unknown) => void
}

export type NextFunction = (err?: unknown) => void

// ─── PQAuth client ────────────────────────────────────────────────────────────

export class PQAuth {
  private readonly apiKey:  string
  private readonly baseUrl: string
  private readonly timeout: number

  constructor(options: PQAuthOptions | string) {
    if (typeof options === 'string') {
      this.apiKey  = options
      this.baseUrl = 'https://pqauth-core.gdbok.workers.dev'
      this.timeout = 10000
    } else {
      this.apiKey  = options.apiKey
      this.baseUrl = options.baseUrl ?? 'https://pqauth-core.gdbok.workers.dev'
      this.timeout = options.timeout ?? 10000
    }

    if (!this.apiKey || !this.apiKey.startsWith('pqa_')) {
      throw new PQAuthError(
        'Invalid API key. Keys must start with "pqa_". Get one at https://pqauth-dashboard.pages.dev',
        'INVALID_API_KEY'
      )
    }
  }

  // ── Private: fetch wrapper ──────────────────────────────────────────────────

  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeout)

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

  // ── sign() ──────────────────────────────────────────────────────────────────

  /**
   * Sign a token for an authenticated user.
   * Call this after verifying the user's credentials in your own system.
   *
   * @example
   * const { token } = await pqauth.sign({
   *   sub: user.id,
   *   email: user.email,
   *   role: 'admin',
   *   expiresInSeconds: 3600
   * })
   */
  async sign(options: SignOptions): Promise<SignResult> {
    if (!options.sub) {
      throw new PQAuthError('"sub" is required', 'MISSING_SUB')
    }

    return this.request<SignResult>('/sign', {
      method: 'POST',
      body: JSON.stringify(options),
    })
  }

  // ── verify() ────────────────────────────────────────────────────────────────

  /**
   * Verify a PQAuth token.
   * Returns { valid: true, payload } if valid, or { valid: false, error } if not.
   * Never throws — safe to use in middleware.
   *
   * @example
   * const { valid, payload } = await pqauth.verify(token)
   * if (!valid) return res.status(401).json({ error: 'Unauthorized' })
   * console.log(payload.sub) // user id
   */
  async verify(token: PQToken): Promise<VerifyResult> {
    try {
      const data = await this.request<VerifyResult & { payload: TokenPayload }>('/verify', {
        method: 'POST',
        body: JSON.stringify({ token }),
      })
      return { valid: true, payload: data.payload }
    } catch (err) {
      if (err instanceof PQAuthError) {
        return { valid: false, payload: null, error: err.message }
      }
      return { valid: false, payload: null, error: 'Unknown error' }
    }
  }

  // ── middleware() ─────────────────────────────────────────────────────────────

  /**
   * Express / Fastify middleware.
   * Reads the token from the Authorization header (Bearer token).
   * Attaches payload to req.user if valid.
   *
   * @example
   * // Express
   * app.use('/api', pqauth.middleware())
   *
   * // Fastify
   * fastify.addHook('preHandler', pqauth.middleware())
   */
  middleware() {
    return async (
      req: MiddlewareRequest & { user?: TokenPayload },
      res: MiddlewareResponse,
      next: NextFunction
    ) => {
      const authHeader = req.headers['authorization']
      const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader

      if (!headerValue?.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Authorization header required (Bearer <token>)'
        })
      }

      let token: PQToken
      try {
        token = JSON.parse(
          Buffer.from(headerValue.slice(7), 'base64').toString('utf8')
        )
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

  // ── health() ────────────────────────────────────────────────────────────────

  /**
   * Check the PQAuth service status.
   *
   * @example
   * const health = await pqauth.health()
   * console.log(health.quantumResistant) // true
   */
  async health(): Promise<HealthResult> {
    const res = await fetch(`${this.baseUrl}/health`)
    return res.json()
  }
}

// ─── Default export ───────────────────────────────────────────────────────────

export default PQAuth
