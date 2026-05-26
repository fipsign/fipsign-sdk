// src/index.ts
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
var PQAuthError = class extends Error {
  constructor(message, code, status) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = "PQAuthError";
  }
};
function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function toBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function verifyLocally(token, publicKeyB64) {
  if (token.algorithm !== "ML-DSA-65") {
    throw new PQAuthError(`Unsupported algorithm: ${token.algorithm}`, "UNSUPPORTED_ALGORITHM");
  }
  const publicKey = fromBase64(publicKeyB64);
  const signature = fromBase64(token.signature);
  const message = new TextEncoder().encode(token.payload);
  const isValid = ml_dsa65.verify(signature, message, publicKey);
  if (!isValid) {
    throw new PQAuthError(
      "Invalid signature \u2014 token was tampered with or not issued by this server",
      "INVALID_SIGNATURE"
    );
  }
  const payload = JSON.parse(atob(token.payload));
  const now = Math.floor(Date.now() / 1e3);
  if (payload.exp < now) {
    throw new PQAuthError(`Token expired ${now - payload.exp} seconds ago`, "TOKEN_EXPIRED");
  }
  return payload;
}
function verifyCertLocally(cert, rootCert) {
  if (cert.type !== "CA_CERT") {
    throw new PQAuthError("Expected a CA_CERT, got " + cert.type, "INVALID_CERT_TYPE");
  }
  if (rootCert.type !== "CA_ROOT") {
    throw new PQAuthError("Expected a CA_ROOT, got " + rootCert.type, "INVALID_CERT_TYPE");
  }
  if (cert.caId !== rootCert.id) {
    throw new PQAuthError("Certificate was not issued by this CA", "CA_MISMATCH");
  }
  const now = Math.floor(Date.now() / 1e3);
  if (cert.expiresAt !== void 0 && cert.expiresAt < now) {
    throw new PQAuthError(
      `Certificate expired ${now - cert.expiresAt} seconds ago`,
      "CERT_EXPIRED"
    );
  }
  const { signature, ...certWithoutSig } = cert;
  const canonical = JSON.stringify(certWithoutSig, Object.keys(certWithoutSig).sort());
  const msgBytes = new TextEncoder().encode(canonical);
  const sigBytes = fromBase64(signature);
  const pubKey = fromBase64(rootCert.publicKey);
  const isValid = ml_dsa65.verify(sigBytes, msgBytes, pubKey);
  if (!isValid) {
    throw new PQAuthError(
      "Invalid certificate signature \u2014 not issued by this CA",
      "INVALID_CERT_SIGNATURE"
    );
  }
}
async function generateKeyPair() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const keys = ml_dsa65.keygen(seed);
  seed.fill(0);
  return {
    publicKey: toBase64(keys.publicKey),
    secretKey: toBase64(keys.secretKey)
  };
}
var PQAuth = class {
  constructor(options) {
    this.cachedKey = null;
    this.keyTTL = 3600;
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
    this.webhooks = {
      register: (options) => this.request("/webhooks", { method: "POST", body: JSON.stringify(options) }),
      get: () => this.request("/webhooks"),
      delete: () => this.request("/webhooks", { method: "DELETE" }),
      test: () => this.request("/webhooks/test", { method: "POST" })
    };
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
    this.ca = {
      /**
       * Issue a certificate signed by this project's CA.
       * Costs 1 token per call.
       */
      issue: (options) => this.request("/ca/issue", {
        method: "POST",
        body: JSON.stringify(options)
      }),
      /**
       * Revoke a certificate immediately.
       * Costs 1 token per call.
       */
      revokeCert: (certId, reason) => this.request("/ca/revoke", {
        method: "POST",
        body: JSON.stringify({ certId, reason })
      }),
      /**
       * Get a certificate by ID.
       * Free — no token cost.
       */
      getCert: (certId) => this.request(`/ca/certificate/${certId}`),
      /**
       * Get the Certificate Revocation List for this project's CA.
       * Free — no token cost.
       */
      getCrl: () => this.request("/ca/crl"),
      /**
       * Verify a certificate entirely offline using the CA root certificate.
       * No API call — uses ML-DSA-65 locally.
       * Does NOT check revocation — call getCrl() and isCertRevoked() for that.
       */
      verifyCert: (cert, rootCert) => {
        try {
          verifyCertLocally(cert, rootCert);
          return { valid: true, cert };
        } catch (err) {
          const message = err instanceof PQAuthError ? err.message : "Unknown error";
          return { valid: false, error: message };
        }
      },
      /**
       * Check if a certificate appears in a CRL.
       * Offline — pass the result of getCrl().
       */
      isCertRevoked: (cert, crl) => {
        return crl.some((entry) => entry.certId === cert.id);
      }
    };
    if (typeof options === "string") {
      this.apiKey = options;
      this.baseUrl = "https://api.fipsign.dev";
      this.timeout = 1e4;
      this.localVerify = false;
    } else {
      this.apiKey = options.apiKey;
      this.baseUrl = options.baseUrl ?? "https://api.fipsign.dev";
      this.timeout = options.timeout ?? 1e4;
      this.localVerify = options.localVerify ?? false;
    }
    if (!this.apiKey?.startsWith("pqa_")) {
      throw new PQAuthError(
        'Invalid API key \u2014 keys must start with "pqa_". Get one at https://app.fipsign.dev',
        "INVALID_API_KEY"
      );
    }
  }
  // ── Private: fetch wrapper ──────────────────────────────────────────────────
  async request(path, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...options,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.apiKey,
          ...options.headers
        }
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new PQAuthError(
          data.error ?? `Request failed with status ${res.status}`,
          "API_ERROR",
          res.status
        );
      }
      return data;
    } catch (err) {
      if (err instanceof PQAuthError) throw err;
      if (err instanceof Error && err.name === "AbortError") {
        throw new PQAuthError("Request timed out", "TIMEOUT");
      }
      throw new PQAuthError(
        `Network error: ${err instanceof Error ? err.message : "unknown"}`,
        "NETWORK_ERROR"
      );
    } finally {
      clearTimeout(timer);
    }
  }
  // ── Private: public key with cache ──────────────────────────────────────────
  async getPublicKey() {
    const now = Math.floor(Date.now() / 1e3);
    if (this.cachedKey && now - this.cachedKey.fetchedAt < this.cachedKey.ttlSeconds) {
      return this.cachedKey.publicKey;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}/public-key`, { signal: controller.signal });
      const data = await res.json();
      this.cachedKey = { publicKey: data.publicKey, fetchedAt: now, ttlSeconds: this.keyTTL };
      return data.publicKey;
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new PQAuthError("Public key fetch timed out", "TIMEOUT");
      }
      throw new PQAuthError(
        `Failed to fetch public key: ${err instanceof Error ? err.message : "unknown"}`,
        "NETWORK_ERROR"
      );
    } finally {
      clearTimeout(timer);
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
  async sign(options) {
    if (!options.sub) throw new PQAuthError('"sub" is required', "MISSING_SUB");
    return this.request("/sign", { method: "POST", body: JSON.stringify(options) });
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
  async verify(token) {
    return this.localVerify ? this.verifyLocal(token) : this.verifyRemote(token);
  }
  async verifyRemote(token) {
    try {
      const data = await this.request("/verify", {
        method: "POST",
        body: JSON.stringify({ token })
      });
      return { valid: true, payload: data.payload, local: false };
    } catch (err) {
      const message = err instanceof PQAuthError ? err.message : "Unknown error";
      return { valid: false, payload: null, error: message, local: false };
    }
  }
  async verifyLocal(token) {
    try {
      const publicKey = await this.getPublicKey();
      const payload = verifyLocally(token, publicKey);
      return { valid: true, payload, local: true };
    } catch (err) {
      if (err instanceof PQAuthError && err.code === "INVALID_SIGNATURE") {
        this.cachedKey = null;
        try {
          const publicKey = await this.getPublicKey();
          const payload = verifyLocally(token, publicKey);
          return { valid: true, payload, local: true };
        } catch {
        }
      }
      const message = err instanceof PQAuthError ? err.message : "Unknown error";
      return { valid: false, payload: null, error: message, local: true };
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
  async revoke(token, reason) {
    return this.request("/revoke", {
      method: "POST",
      body: JSON.stringify({ token, reason })
    });
  }
  // ── usage() ─────────────────────────────────────────────────────────────────
  /**
   * Get current token balance and 6-month usage history.
   */
  async usage() {
    return this.request("/usage");
  }
  // ── middleware() ─────────────────────────────────────────────────────────────
  /**
   * Express / Fastify middleware. Node.js only.
   *
   * @example
   * app.use('/api', pqauth.middleware())
   */
  middleware() {
    return async (req, res, next) => {
      const authHeader = req.headers["authorization"];
      const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
      if (!headerValue?.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Authorization header required (Bearer <token>)" });
      }
      let token;
      try {
        const b64 = headerValue.slice(7);
        const decoded = typeof atob !== "undefined" ? atob(b64) : Buffer.from(b64, "base64").toString("utf8");
        token = JSON.parse(decoded);
      } catch {
        return res.status(401).json({ error: "Invalid token format" });
      }
      const result = await this.verify(token);
      if (!result.valid) {
        return res.status(401).json({ error: result.error ?? "Invalid token" });
      }
      req.user = result.payload;
      next();
    };
  }
  // ── preloadPublicKey() ───────────────────────────────────────────────────────
  /**
   * Preload and cache the server's public key at startup.
   *
   * @example
   * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
   * await pqauth.preloadPublicKey()
   */
  async preloadPublicKey() {
    await this.getPublicKey();
  }
  // ── health() ─────────────────────────────────────────────────────────────────
  /**
   * Check the health of the PQAuth service.
   */
  async health() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}/health`, { signal: controller.signal });
      return res.json();
    } finally {
      clearTimeout(timer);
    }
  }
};
var index_default = PQAuth;
export {
  PQAuth,
  PQAuthError,
  index_default as default,
  generateKeyPair
};
