/**
 * pqauth-sdk v0.4.3
 *
 * Post-quantum signing SDK for Node.js and the browser.
 * Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.
 *
 * Sign anything: users, orders, documents, devices, events.
 * The only required field is `sub` — any string identifying the entity.
 */
interface PQAuthOptions {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
    localVerify?: boolean;
}
interface SignOptions {
    sub: string;
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
        projectId: string;
        tokenCost: number;
        source: 'free' | 'pack' | 'free+pack';
    };
    usage: {
        freeRemaining: number;
        packRemaining: number;
        totalRemaining: number;
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
        month: string;
        freeUsed: number;
        freeRemaining: number;
        freeLimit: number;
        packRemaining: number;
        totalRemaining: number;
    };
    monthlyHistory: {
        month: string;
        tokensUsed: number;
        fromFree: number;
        fromPack: number;
    }[];
    packs: {
        id: string;
        packType: string;
        tokensPurchased: number;
        purchasedAt: number;
        paymentRef: string | null;
    }[];
    developer: {
        email: string;
    };
    note: string;
}
type WebhookEvent = 'token.signed' | 'token.rejected' | 'token.revoked' | 'limit.warning' | 'limit.reached';
interface WebhookResult {
    webhook: {
        url: string;
        events: WebhookEvent[];
        secret: string;
    };
}
interface WebhookGetResult {
    webhook: {
        url: string;
        events: WebhookEvent[];
    } | null;
}
interface HealthResult {
    status: string;
    algorithm: string;
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
    sign(options: SignOptions): Promise<SignResult>;
    /**
     * Verify a PQAuth token.
     *
     * Never throws — returns { valid: false, error } on failure.
     *
     * If localVerify: true, verification happens entirely in memory (~1ms, no API call).
     * Local verification does not check the revocation list — use remote verification
     * for sensitive operations such as payments or admin actions.
     *
     * When server keys are rotated, the SDK automatically detects the mismatch,
     * refreshes the cached public key, and retries — no action needed on your end.
     *
     * @example
     * const { valid, payload } = await pqauth.verify(token)
     * if (!valid) return res.status(401).json({ error: 'Unauthorized' })
     */
    verify(token: PQToken): Promise<VerifyResult>;
    private verifyRemote;
    private verifyLocal;
    /**
     * Revoke a token immediately.
     *
     * Future verify() calls will reject it even if the signature is valid
     * and the token has not yet expired.
     *
     * Revocation always requires an API call, even when localVerify is enabled.
     *
     * @example
     * await pqauth.revoke(token, 'user logged out')
     * await pqauth.revoke(token, 'suspicious activity detected')
     */
    revoke(token: PQToken, reason?: string): Promise<RevokeResult>;
    /**
     * Get current token balance and 6-month usage history.
     *
     * Free tokens reset on the 1st of each month (UTC) and do not accumulate.
     * Pack tokens never expire and accumulate across purchases.
     * All projects under the same account share a single pool.
     */
    usage(): Promise<UsageResult>;
    /**
     * Manage webhook configuration for real-time event notifications.
     *
     * Events: token.signed · token.rejected · token.revoked · limit.warning · limit.reached
     *
     * @example
     * const { webhook } = await pqauth.webhooks.register({
     *   url:    'https://yourapp.com/webhooks/pqauth',
     *   events: ['limit.warning', 'limit.reached', 'token.revoked'],
     * })
     * console.log(webhook.secret) // store this — it won't be shown again
     */
    readonly webhooks: {
        register: (options: {
            url: string;
            events?: WebhookEvent[];
        }) => Promise<WebhookResult>;
        get: () => Promise<WebhookGetResult>;
        delete: () => Promise<{
            success: boolean;
        }>;
        test: () => Promise<{
            success: boolean;
            message: string;
        }>;
    };
    /**
     * Express / Fastify middleware. Node.js only.
     *
     * Reads Authorization: Bearer <base64(token)> and attaches the decoded
     * payload to req.user. Returns 401 if the token is missing or invalid.
     *
     * @example
     * app.use('/api', pqauth.middleware())
     *
     * app.get('/api/profile', (req, res) => {
     *   res.json({ user: req.user })
     * })
     */
    middleware(): (req: MiddlewareRequest & {
        user?: TokenPayload;
    }, res: MiddlewareResponse, next: NextFunction) => Promise<void>;
    /**
     * Preload and cache the server's public key at startup.
     *
     * Recommended when using localVerify: true to avoid first-request latency.
     *
     * @example
     * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
     * await pqauth.preloadPublicKey() // call once at startup
     */
    preloadPublicKey(): Promise<void>;
    /**
     * Check the health of the PQAuth service.
     */
    health(): Promise<HealthResult>;
}

export { type HealthResult, type MiddlewareRequest, type MiddlewareResponse, type NextFunction, PQAuth, PQAuthError, type PQAuthOptions, type PQToken, type RevokeResult, type SignOptions, type SignResult, type TokenPayload, type UsageResult, type VerifyResult, type WebhookEvent, type WebhookGetResult, type WebhookResult, PQAuth as default };
