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
interface PQAuthOptions {
    /** Your PQAuth API key (starts with pqa_) */
    apiKey: string;
    /** API base URL. Defaults to the PQAuth cloud service. */
    baseUrl?: string;
    /** Request timeout in milliseconds. Default: 10000 */
    timeout?: number;
}
interface SignOptions {
    /** Subject — userId or email that identifies the end user */
    sub: string;
    /** Optional email of the end user */
    email?: string;
    /** Optional role (e.g. 'admin', 'user', 'merchant') */
    role?: string;
    /** Token expiry in seconds. Default: 3600 (1 hour) */
    expiresInSeconds?: number;
    /** Any additional custom fields */
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
interface HealthResult {
    status: string;
    algorithm: string;
    standard: string;
    quantumResistant: boolean;
    version: string;
}
declare class PQAuthError extends Error {
    readonly code: string;
    readonly status?: number | undefined;
    constructor(message: string, code: string, status?: number | undefined);
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
declare class PQAuth {
    private readonly apiKey;
    private readonly baseUrl;
    private readonly timeout;
    constructor(options: PQAuthOptions | string);
    private request;
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
    sign(options: SignOptions): Promise<SignResult>;
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
    verify(token: PQToken): Promise<VerifyResult>;
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
    middleware(): (req: MiddlewareRequest & {
        user?: TokenPayload;
    }, res: MiddlewareResponse, next: NextFunction) => Promise<void>;
    /**
     * Check the PQAuth service status.
     *
     * @example
     * const health = await pqauth.health()
     * console.log(health.quantumResistant) // true
     */
    health(): Promise<HealthResult>;
}

export { type HealthResult, type MiddlewareRequest, type MiddlewareResponse, type NextFunction, PQAuth, PQAuthError, type PQAuthOptions, type PQToken, type SignOptions, type SignResult, type TokenPayload, type VerifyResult, PQAuth as default };
