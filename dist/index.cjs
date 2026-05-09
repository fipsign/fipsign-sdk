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
var PQAuthError = class extends Error {
  constructor(message, code, status) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = "PQAuthError";
  }
};
var PQAuth = class {
  constructor(options) {
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
    } else {
      this.apiKey = options.apiKey;
      this.baseUrl = options.baseUrl ?? "https://pqauth-core.gdbok.workers.dev";
      this.timeout = options.timeout ?? 1e4;
    }
    if (!this.apiKey?.startsWith("pqa_")) {
      throw new PQAuthError(
        'Invalid API key. Keys must start with "pqa_". Get one at https://pqauth-dashboard.pages.dev',
        "INVALID_API_KEY"
      );
    }
  }
  // ── Private fetch wrapper ───────────────────────────────────────────────────
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
   * Never throws — returns { valid: false, error } on failure.
   *
   * @example
   * const { valid, payload } = await pqauth.verify(token)
   * if (!valid) return res.status(401).json({ error: 'Unauthorized' })
   */
  async verify(token) {
    try {
      const data = await this.request("/verify", {
        method: "POST",
        body: JSON.stringify({ token })
      });
      return { valid: true, payload: data.payload };
    } catch (err) {
      if (err instanceof PQAuthError) return { valid: false, payload: null, error: err.message };
      return { valid: false, payload: null, error: "Unknown error" };
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
  async revoke(token, reason) {
    return this.request("/revoke", {
      method: "POST",
      body: JSON.stringify({ token, reason })
    });
  }
  // ── usage() ─────────────────────────────────────────────────────────────────
  /**
   * Get current month usage and 6-month history.
   *
   * @example
   * const { current } = await pqauth.usage()
   * console.log(`${current.count} / ${current.limit} tokens used`)
   */
  async usage() {
    return this.request("/usage");
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
  // ── health() ────────────────────────────────────────────────────────────────
  /**
   * Check the PQAuth service status.
   */
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
