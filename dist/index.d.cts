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
interface PQAuthOptions {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
}
interface SignOptions {
    sub: string;
    email?: string;
    role?: string;
    expiresInSeconds?: number;
    [key: string]: unknown;
}
interface PQToken {
    payload: string;
    signature: string;
    algorithm: string;
    issuedAt: number;
}
interface SignResult {
    token: PQToken;
    meta: {
        algorithm: string;
        standard: string;
        quantumResistant: boolean;
        expiresIn: number;
        issuedFor: string;
    };
    usage: {
        count: number;
        limit: number;
        remaining: number;
        month: string;
    };
}
interface VerifyResult {
    valid: boolean;
    payload: TokenPayload | null;
    error?: string;
}
interface TokenPayload {
    sub: string;
    email?: string;
    role?: string;
    iat: number;
    exp: number;
    [key: string]: unknown;
}
interface RevokeResult {
    success: boolean;
    message: string;
    revokedAt: number;
    sub: string;
}
interface UsageResult {
    current: {
        count: number;
        month: string;
        limit: number;
        remaining: number;
        plan: string;
    };
    history: {
        month: string;
        count: number;
    }[];
    developer: {
        email: string;
        plan: string;
    };
}
type WebhookEvent = 'token.signed' | 'token.rejected' | 'token.revoked' | 'limit.warning' | 'limit.reached';
interface WebhookResult {
    webhook: {
        url: string;
        events: WebhookEvent[];
        secret: string;
    };
}
interface HealthResult {
    status: string;
    algorithm: string;
    standard: string;
    quantumResistant: boolean;
    version: string;
}
interface MiddlewareRequest {
    headers: {
        [key: string]: string | string[] | undefined;
    };
}
interface MiddlewareResponse {
    status: (code: number) => MiddlewareResponse;
    json: (data: unknown) => void;
}
type NextFunction = (err?: unknown) => void;
declare class PQAuthError extends Error {
    readonly code: string;
    readonly status?: number | undefined;
    constructor(message: string, code: string, status?: number | undefined);
}
declare class PQAuth {
    private readonly apiKey;
    private readonly baseUrl;
    private readonly timeout;
    constructor(options: PQAuthOptions | string);
    private request;
    /**
     * Sign a token for an authenticated user.
     *
     * @example
     * const { token } = await pqauth.sign({ sub: user.id, email: user.email })
     */
    sign(options: SignOptions): Promise<SignResult>;
    /**
     * Verify a PQAuth token.
     * Never throws — returns { valid: false, error } on failure.
     *
     * @example
     * const { valid, payload } = await pqauth.verify(token)
     * if (!valid) return res.status(401).json({ error: 'Unauthorized' })
     */
    verify(token: PQToken): Promise<VerifyResult>;
    /**
     * Revoke a token immediately.
     * Once revoked, the token will be rejected on any future verify() call.
     *
     * @example
     * // Revoke on logout or when a session is compromised
     * await pqauth.revoke(token, 'user logged out')
     */
    revoke(token: PQToken, reason?: string): Promise<RevokeResult>;
    /**
     * Get current month usage and 6-month history.
     *
     * @example
     * const { current } = await pqauth.usage()
     * console.log(`${current.count} / ${current.limit} tokens used`)
     */
    usage(): Promise<UsageResult>;
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
    readonly webhooks: {
        register: (options: {
            url: string;
            events?: WebhookEvent[];
        }) => Promise<WebhookResult>;
        get: () => Promise<{
            webhook: WebhookResult["webhook"] | null;
        }>;
        delete: () => Promise<{
            success: boolean;
        }>;
        test: () => Promise<{
            success: boolean;
            message: string;
        }>;
    };
    /**
     * Express / Fastify middleware.
     * Reads the token from the Authorization: Bearer header.
     * Attaches payload to req.user if valid.
     *
     * @example
     * app.use('/api', pqauth.middleware())
     */
    middleware(): (req: MiddlewareRequest & {
        user?: TokenPayload;
    }, res: MiddlewareResponse, next: NextFunction) => Promise<void>;
    /**
     * Check the PQAuth service status.
     */
    health(): Promise<HealthResult>;
}

export { type HealthResult, type MiddlewareRequest, type MiddlewareResponse, type NextFunction, PQAuth, PQAuthError, type PQAuthOptions, type PQToken, type RevokeResult, type SignOptions, type SignResult, type TokenPayload, type UsageResult, type VerifyResult, type WebhookEvent, type WebhookResult, PQAuth as default };
