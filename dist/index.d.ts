/**
 * fipsign-sdk v0.6.0
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
interface PQCert {
    type: 'CA_ROOT' | 'CA_CERT';
    id: string;
    subject: string;
    publicKey: string;
    caId?: string;
    issuedAt: number;
    expiresAt?: number;
    algorithm: 'ML-DSA-65';
    standard: 'NIST FIPS 204';
    meta?: Record<string, unknown>;
    signature: string;
}
interface CaIssueCertOptions {
    subject: string;
    publicKey: string;
    expiresInSeconds: number;
    meta?: Record<string, unknown>;
}
interface CaIssueCertResult {
    certificate: PQCert;
    meta: {
        certId: string;
        caId: string;
        subject: string;
        issuedAt: number;
        expiresAt: number;
        algorithm: string;
        standard: string;
    };
    usage: {
        freeRemaining: number;
        packRemaining: number;
        totalRemaining: number;
    };
}
interface CaRevokeCertResult {
    certId: string;
    revokedAt: number;
    reason: string | null;
    usage: {
        freeRemaining: number;
        packRemaining: number;
        totalRemaining: number;
    };
}
interface CaCertStatus {
    revoked: boolean;
    expired: boolean;
    revokedAt: number | null;
    expiresAt: number;
}
interface CaGetCertResult {
    certificate: PQCert;
    status: CaCertStatus;
}
interface CrlEntry {
    certId: string;
    revokedAt: number;
    reason: string | null;
}
interface CaGetCrlResult {
    caId: string;
    subject: string;
    crl: CrlEntry[];
    generatedAt: number;
}
interface VerifyCertResult {
    valid: boolean;
    cert?: PQCert;
    error?: string;
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
declare function generateKeyPair(): Promise<{
    publicKey: string;
    secretKey: string;
}>;
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
     * @example
     * await pqauth.revoke(token, 'user logged out')
     */
    revoke(token: PQToken, reason?: string): Promise<RevokeResult>;
    /**
     * Get current token balance and 6-month usage history.
     */
    usage(): Promise<UsageResult>;
    /**
     * Manage webhook configuration for real-time event notifications.
     *
     * @example
     * const { webhook } = await pqauth.webhooks.register({
     *   url:    'https://yourapp.com/webhooks/pqauth',
     *   events: ['limit.warning', 'limit.reached', 'token.revoked'],
     * })
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
    readonly ca: {
        /**
         * Issue a certificate signed by this project's CA.
         * Costs 1 token per call.
         */
        issue: (options: CaIssueCertOptions) => Promise<CaIssueCertResult>;
        /**
         * Revoke a certificate immediately.
         * Costs 1 token per call.
         */
        revokeCert: (certId: string, reason?: string) => Promise<CaRevokeCertResult>;
        /**
         * Get a certificate by ID.
         * Free — no token cost.
         */
        getCert: (certId: string) => Promise<CaGetCertResult>;
        /**
         * Get the Certificate Revocation List for this project's CA.
         * Free — no token cost.
         */
        getCrl: () => Promise<CaGetCrlResult>;
        /**
         * Verify a certificate entirely offline using the CA root certificate.
         * No API call — uses ML-DSA-65 locally.
         * Does NOT check revocation — call getCrl() and isCertRevoked() for that.
         */
        verifyCert: (cert: PQCert, rootCert: PQCert) => VerifyCertResult;
        /**
         * Check if a certificate appears in a CRL.
         * Offline — pass the result of getCrl().
         */
        isCertRevoked: (cert: PQCert, crl: CrlEntry[]) => boolean;
    };
    /**
     * Express / Fastify middleware. Node.js only.
     *
     * @example
     * app.use('/api', pqauth.middleware())
     */
    middleware(): (req: MiddlewareRequest & {
        user?: TokenPayload;
    }, res: MiddlewareResponse, next: NextFunction) => Promise<void>;
    /**
     * Preload and cache the server's public key at startup.
     *
     * @example
     * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
     * await pqauth.preloadPublicKey()
     */
    preloadPublicKey(): Promise<void>;
    /**
     * Check the health of the PQAuth service.
     */
    health(): Promise<HealthResult>;
}

export { type CaCertStatus, type CaGetCertResult, type CaGetCrlResult, type CaIssueCertOptions, type CaIssueCertResult, type CaRevokeCertResult, type CrlEntry, type HealthResult, type MiddlewareRequest, type MiddlewareResponse, type NextFunction, PQAuth, PQAuthError, type PQAuthOptions, type PQCert, type PQToken, type RevokeResult, type SignOptions, type SignResult, type TokenPayload, type UsageResult, type VerifyCertResult, type VerifyResult, type WebhookEvent, type WebhookGetResult, type WebhookResult, PQAuth as default, generateKeyPair };
