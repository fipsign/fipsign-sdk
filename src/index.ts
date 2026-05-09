/**
 * pqauth-sdk
 *
 * Post-quantum authentication SDK for Node.js and the browser.
 * Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.
 *
 * @example
 * import { PQAuth } from 'pqauth-sdk'
 * const pqauth = new PQAuth('pqa_your_api_key')
 *
 * const { token } = await pqauth.sign({ sub: 'user_123' })
 * const { valid, payload } = await pqauth.verify(token)
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PQAuthOptions {
  apiKey:   string
  baseUrl?: string
  timeout?: number
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
  }
  usage: {
    count:     number
    limit:     number
    remaining: number
    month:     string
  }
}

export interface VerifyResult {
  valid:    boolean
  payload:  TokenPayload | null
  error?:   string
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

export interface UsageResult {
  current: {
    count:     number
    month:     string
    limit:     number
    remaining: number
    plan:      string
  }
  history: { month: string; count: number }[]
  developer: { email: string; plan: string }
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

    if (!this.apiKey?.startsWith('pqa_')) {
      throw new PQAuthError(
        'Invalid API key. Keys must start with "pqa_". Get one at https://pqauth-dashboard.pages.dev',
        'INVALID_API_KEY'
      )
    }
  }

  // ── Private fetch wrapper ───────────────────────────────────────────────────

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
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
   *
   * @example
   * const { token } = await pqauth.sign({ sub: user.id, email: user.email })
   */
  async sign(options: SignOptions): Promise<SignResult> {
    if (!options.sub) throw new PQAuthError('"sub" is required', 'MISSING_SUB')
    return this.request<SignResult>('/sign', {
      method: 'POST',
      body:   JSON.stringify(options),
    })
  }

  // ── verify() ────────────────────────────────────────────────────────────────

  /**
   * Verify a PQAuth token.
   * Never throws — returns { valid: false, error } on failure.
   *
   * @example
   * const { valid, payload } = await pqauth.verify(token)
   * if (!valid) return res.status(401).json({ error: 'Unauthorized' })
   */
  async verify(token: PQToken): Promise<VerifyResult> {
    try {
      const data = await this.request<VerifyResult & { payload: TokenPayload }>('/verify', {
        method: 'POST',
        body:   JSON.stringify({ token }),
      })
      return { valid: true, payload: data.payload }
    } catch (err) {
      if (err instanceof PQAuthError) return { valid: false, payload: null, error: err.message }
      return { valid: false, payload: null, error: 'Unknown error' }
    }
  }

  // ── revoke() ────────────────────────────────────────────────────────────────

  /**
   * Revoke a token immediately.
   * Once revoked, the token will be rejected on any future verify() call.
   *
   * @example
   * // Revoke on logout or when a session is compromised
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
   *
   * @example
   * const { current } = await pqauth.usage()
   * console.log(`${current.count} / ${current.limit} tokens used`)
   */
  async usage(): Promise<UsageResult> {
    return this.request<UsageResult>('/usage')
  }

  // ── webhooks ────────────────────────────────────────────────────────────────

  /**
   * Register a webhook URL to receive event notifications.
   *
   * @example
   * const { webhook } = await pqauth.webhooks.register({
   *   url: 'https://myapp.com/webhooks/pqauth',
   *   events: ['limit.warning', 'limit.reached', 'token.revoked']
   * })
   * console.log(webhook.secret) // store this to verify incoming webhooks
   */
  readonly webhooks = {
    register: (options: { url: string; events?: WebhookEvent[] }): Promise<WebhookResult> =>
      this.request<WebhookResult>('/webhooks', {
        method: 'POST',
        body:   JSON.stringify(options),
      }),

    get: (): Promise<{ webhook: WebhookResult['webhook'] | null }> =>
      this.request('/webhooks'),

    delete: (): Promise<{ success: boolean }> =>
      this.request('/webhooks', { method: 'DELETE' }),

    test: (): Promise<{ success: boolean; message: string }> =>
      this.request('/webhooks/test', { method: 'POST' }),
  }

  // ── middleware() ─────────────────────────────────────────────────────────────

  /**
   * Express / Fastify middleware.
   * Reads the token from the Authorization: Bearer header.
   * Attaches payload to req.user if valid.
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
        token = JSON.parse(Buffer.from(headerValue.slice(7), 'base64').toString('utf8'))
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
   */
  async health(): Promise<HealthResult> {
    const res = await fetch(`${this.baseUrl}/health`)
    return res.json()
  }
}

export default PQAuth
