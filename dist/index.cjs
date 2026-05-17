"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  PQAuth: () => PQAuth,
  PQAuthError: () => PQAuthError,
  default: () => index_default
});
module.exports = __toCommonJS(index_exports);
var import_ml_dsa = require("@noble/post-quantum/ml-dsa.js");
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
function verifyLocally(token, publicKeyB64) {
  if (token.algorithm !== "ML-DSA-65") {
    throw new PQAuthError(`Unsupported algorithm: ${token.algorithm}`, "UNSUPPORTED_ALGORITHM");
  }
  const publicKey = fromBase64(publicKeyB64);
  const signature = fromBase64(token.signature);
  const message = new TextEncoder().encode(token.payload);
  const isValid = import_ml_dsa.ml_dsa65.verify(signature, message, publicKey);
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
var PQAuth = class {
  // refresh public key every hour
  constructor(options) {
    this.cachedKey = null;
    this.keyTTL = 3600;
    // ── webhooks ────────────────────────────────────────────────────────────────
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
    this.webhooks = {
      register: (options) => this.request("/webhooks", { method: "POST", body: JSON.stringify(options) }),
      get: () => this.request("/webhooks"),
      delete: () => this.request("/webhooks", { method: "DELETE" }),
      test: () => this.request("/webhooks/test", { method: "POST" })
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
  // ── Private: fetch wrapper with timeout and error normalization ─────────────
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
   * When server keys are rotated, the SDK automatically detects the mismatch,
   * refreshes the cached public key, and retries — no action needed on your end.
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
   * Revocation always requires an API call, even when localVerify is enabled.
   *
   * @example
   * await pqauth.revoke(token, 'user logged out')
   * await pqauth.revoke(token, 'suspicious activity detected')
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
   *
   * Free tokens reset on the 1st of each month (UTC) and do not accumulate.
   * Pack tokens never expire and accumulate across purchases.
   * All projects under the same account share a single pool.
   */
  async usage() {
    return this.request("/usage");
  }
  // ── middleware() ─────────────────────────────────────────────────────────────
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
   * Recommended when using localVerify: true to avoid first-request latency.
   *
   * @example
   * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
   * await pqauth.preloadPublicKey() // call once at startup
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  PQAuth,
  PQAuthError
});
