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
    throw new PQAuthError("Invalid signature \u2014 token was tampered with or not issued by this server", "INVALID_SIGNATURE");
  }
  const payload = JSON.parse(atob(token.payload));
  const now = Math.floor(Date.now() / 1e3);
  if (payload.exp < now) {
    const ago = now - payload.exp;
    throw new PQAuthError(`Token expired ${ago} seconds ago`, "TOKEN_EXPIRED");
  }
  return payload;
}
var PQAuth = class {
  // refresh public key every hour
  constructor(options) {
    this.cachedKey = null;
    this.keyTTL = 3600;
    // ── webhooks ────────────────────────────────────────────────────────────────
    this.webhooks = {
      register: (options) => this.request("/webhooks", {
        method: "POST",
        body: JSON.stringify(options)
      }),
      get: () => this.request("/webhooks"),
      delete: () => this.request("/webhooks", { method: "DELETE" }),
      test: () => this.request("/webhooks/test", { method: "POST" })
    };
    if (typeof options === "string") {
      this.apiKey = options;
      this.baseUrl = "https://pqauth-core.gdbok.workers.dev";
      this.timeout = 1e4;
      this.localVerify = false;
    } else {
      this.apiKey = options.apiKey;
      this.baseUrl = options.baseUrl ?? "https://pqauth-core.gdbok.workers.dev";
      this.timeout = options.timeout ?? 1e4;
      this.localVerify = options.localVerify ?? false;
    }
    if (!this.apiKey?.startsWith("pqa_")) {
      throw new PQAuthError(
        'Invalid API key. Keys must start with "pqa_". Get one at https://pqauth-dashboard.pages.dev',
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
  // ── Private: get public key (with cache) ────────────────────────────────────
  async getPublicKey() {
    const now = Math.floor(Date.now() / 1e3);
    if (this.cachedKey && now - this.cachedKey.fetchedAt < this.cachedKey.ttlSeconds) {
      return this.cachedKey.publicKey;
    }
    const res = await fetch(`${this.baseUrl}/public-key`);
    const data = await res.json();
    this.cachedKey = {
      publicKey: data.publicKey,
      fetchedAt: now,
      ttlSeconds: this.keyTTL
    };
    return data.publicKey;
  }
  // ── sign() ──────────────────────────────────────────────────────────────────
  /**
   * Sign a token for an authenticated user.
   *
   * @example
   * const { token } = await pqauth.sign({ sub: user.id, email: user.email })
   */
  async sign(options) {
    if (!options.sub) throw new PQAuthError('"sub" is required', "MISSING_SUB");
    return this.request("/sign", {
      method: "POST",
      body: JSON.stringify(options)
    });
  }
  // ── verify() ────────────────────────────────────────────────────────────────
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
  async verify(token) {
    if (this.localVerify) {
      return this.verifyLocal(token);
    }
    return this.verifyRemote(token);
  }
  async verifyRemote(token) {
    try {
      const data = await this.request("/verify", {
        method: "POST",
        body: JSON.stringify({ token })
      });
      return { valid: true, payload: data.payload, local: false };
    } catch (err) {
      if (err instanceof PQAuthError) return { valid: false, payload: null, error: err.message, local: false };
      return { valid: false, payload: null, error: "Unknown error", local: false };
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
   * Future verify() calls will reject it even if the signature is valid.
   *
   * Note: revocation requires an API call even when localVerify is enabled.
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
   * Get current month usage and 6-month history.
   */
  async usage() {
    return this.request("/usage");
  }
  // ── middleware() ─────────────────────────────────────────────────────────────
  /**
   * Express / Fastify middleware.
   * Reads Authorization: Bearer header and attaches payload to req.user.
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
        token = JSON.parse(Buffer.from(headerValue.slice(7), "base64").toString("utf8"));
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
  // ── preloadPublicKey() ────────────────────────────────────────────────────────
  /**
   * Preload and cache the public key.
   * Call this at app startup when using localVerify: true
   * to avoid the first-request latency.
   *
   * @example
   * const pqauth = new PQAuth({ apiKey: 'pqa_...', localVerify: true })
   * await pqauth.preloadPublicKey() // at startup
   */
  async preloadPublicKey() {
    await this.getPublicKey();
  }
  // ── health() ────────────────────────────────────────────────────────────────
  async health() {
    const res = await fetch(`${this.baseUrl}/health`);
    return res.json();
  }
};
var index_default = PQAuth;
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  PQAuth,
  PQAuthError
});
