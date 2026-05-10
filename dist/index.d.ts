/**
 * pqauth-sdk v0.3.0
 *
 * Post-quantum authentication SDK for Node.js and the browser.
 * Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.
 */
interface PQAuthOptions {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
    localVerify?: boolean;
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
    local?: boolean;
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
    private readonly localVerify;
    private cachedKey;
    private readonly keyTTL;
    constructor(options: PQAuthOptions | string);
    private request;
    private getPublicKey;
    /**
     * Sign a token for an authenticated user.
     *
     * @example
     * const { token } = await pqauth.sign({ sub: user.id, email: user.email })
     */
    sign(options: SignOptions): Promise<SignResult>;
    /**
     * Verify a PQAuth token.
     *
     * If localVerify: true was set in the constructor, verification happens
     * entirely in memory using the cached public key — no API call, ~1ms latency.
     *
     * If localVerify: false (default), verification is done by the API.
     *
     * Never throws — returns { valid: false, error } on failure.
     *
     * @example
     * // Online verification (default)
     * const pqauth = new PQAuth('pqa_...')
     * const { valid, payload } = await pqauth.verify(token)
     *
     * // Local verification (no API call, ~1ms)
     * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
     * const { valid, payload, local } = await pqauth.verify(token)
     */
    verify(token: PQToken): Promise<VerifyResult>;
    private verifyRemote;
    private verifyLocal;
    /**
     * Revoke a token immediately.
     * Future verify() calls will reject it even if the signature is valid.
     *
     * Note: revocation requires an API call even when localVerify is enabled.
     *
     * @example
     * await pqauth.revoke(token, 'user logged out')
     */
    revoke(token: PQToken, reason?: string): Promise<RevokeResult>;
    /**
     * Get current month usage and 6-month history.
     */
    usage(): Promise<UsageResult>;
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
     * Reads Authorization: Bearer header and attaches payload to req.user.
     *
     * @example
     * app.use('/api', pqauth.middleware())
     */
    middleware(): (req: MiddlewareRequest & {
        user?: TokenPayload;
    }, res: MiddlewareResponse, next: NextFunction) => Promise<void>;
    /**
     * Preload and cache the public key.
     * Call this at app startup when using localVerify: true
     * to avoid the first-request latency.
     *
     * @example
     * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
     * await pqauth.preloadPublicKey() // at startup
     */
    preloadPublicKey(): Promise<void>;
    health(): Promise<HealthResult>;
}

export { type HealthResult, type MiddlewareRequest, type MiddlewareResponse, type NextFunction, PQAuth, PQAuthError, type PQAuthOptions, type PQToken, type RevokeResult, type SignOptions, type SignResult, type TokenPayload, type UsageResult, type VerifyResult, type WebhookEvent, type WebhookResult, PQAuth as default };
