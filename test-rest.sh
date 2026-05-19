#!/bin/bash
# FIPSign REST API — Integration test
# Tests the backend directly via curl, no SDK involved.
#
# Usage:
#   chmod +x test-rest.sh
#   FIPSIGN_API_KEY=pqa_...              \
#   WEBHOOK_URL=https://webhook.site/... \
#   WEBHOOK_SITE_TOKEN=your-uuid         \
#   ./test-rest.sh
#
# Prerequisites:
#   1. Create a free account at https://app.fipsign.dev
#   2. Create a project and an API key inside that project
#   3. Create a free endpoint at https://webhook.site and copy your UUID
#   4. jq must be installed (brew install jq / apt install jq)

set -euo pipefail

# ─── Required environment variables ───────────────────────────────────────────

if [ -z "${FIPSIGN_API_KEY:-}" ]; then
  echo -e "\033[31mError: FIPSIGN_API_KEY is required.\033[0m"
  echo "Get your API key at https://app.fipsign.dev"
  exit 1
fi

if [ -z "${WEBHOOK_URL:-}" ] || [ -z "${WEBHOOK_SITE_TOKEN:-}" ]; then
  echo -e "\033[31mError: WEBHOOK_URL and WEBHOOK_SITE_TOKEN are required.\033[0m"
  echo "Create a free endpoint at https://webhook.site and copy your UUID."
  echo "  WEBHOOK_URL=https://webhook.site/<your-uuid>"
  echo "  WEBHOOK_SITE_TOKEN=<your-uuid>"
  exit 1
fi

BASE_URL="https://api.fipsign.dev"
API_KEY="$FIPSIGN_API_KEY"

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

PASSED=0
FAILED=0

# ─── Helpers ──────────────────────────────────────────────────────────────────

pass() {
  PASSED=$((PASSED + 1))
  echo -e "${GREEN}  ✓${RESET} $1"
}

fail() {
  FAILED=$((FAILED + 1))
  echo -e "${RED}  ✗${RESET} $1"
  echo -e "    ${DIM}→ $2${RESET}"
}

log() {
  printf "  ${DIM}%-32s${RESET} %s\n" "$1" "$2"
}

section() {
  echo -e "\n${CYAN}${BOLD}── $1${RESET}"
}

api() {
  curl -s --max-time 15 "$@"
}

# ─── Start ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}FIPSign REST API — Integration Test${RESET}"
echo -e "${DIM}curl · $(date -u +"%Y-%m-%dT%H:%M:%SZ")${RESET}"
echo ""

# ─── 01 Health ────────────────────────────────────────────────────────────────
section "01 · Health check"

HEALTH=$(api "$BASE_URL/health")
STATUS=$(echo "$HEALTH" | jq -r '.status')
ALGORITHM=$(echo "$HEALTH" | jq -r '.algorithm')
QR=$(echo "$HEALTH" | jq -r '.quantumResistant')
VERSION=$(echo "$HEALTH" | jq -r '.version')
SUCCESS=$(echo "$HEALTH" | jq -r '.success')

if [ "$SUCCESS" = "true" ] && [ "$STATUS" = "ok" ] && [ "$ALGORITHM" = "ML-DSA-65" ] && [ "$QR" = "true" ] && [ -n "$VERSION" ]; then
  log "status"           "$STATUS"
  log "algorithm"        "$ALGORITHM"
  log "quantumResistant" "$QR"
  log "version"          "$VERSION"
  pass "GET /health — correct fields returned"
else
  fail "GET /health" "unexpected response: $HEALTH"
fi

# ─── 02 Public key ────────────────────────────────────────────────────────────
section "02 · Public key"

PUBKEY_RESP=$(api "$BASE_URL/public-key")
PK_SUCCESS=$(echo "$PUBKEY_RESP" | jq -r '.success')
PK=$(echo "$PUBKEY_RESP" | jq -r '.publicKey')
PK_ALG=$(echo "$PUBKEY_RESP" | jq -r '.algorithm')

if [ "$PK_SUCCESS" = "true" ] && [ -n "$PK" ] && [ "$PK_ALG" = "ML-DSA-65" ]; then
  log "algorithm"  "$PK_ALG"
  log "publicKey"  "${PK:0:32}..."
  pass "GET /public-key — returns ML-DSA-65 public key"
else
  fail "GET /public-key" "unexpected response: $PUBKEY_RESP"
fi

# ─── 03 Sign ──────────────────────────────────────────────────────────────────
section "03 · POST /sign"

SIGN_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"user_test","email":"test@example.com","role":"admin","expiresInSeconds":3600}')

SIGN_SUCCESS=$(echo "$SIGN_RESP" | jq -r '.success')
TOKEN_ALG=$(echo "$SIGN_RESP" | jq -r '.token.algorithm')
TOKEN_IAT=$(echo "$SIGN_RESP" | jq -r '.token.issuedAt')
META_COST=$(echo "$SIGN_RESP" | jq -r '.meta.tokenCost')
META_SOURCE=$(echo "$SIGN_RESP" | jq -r '.meta.source')
META_PROJECT=$(echo "$SIGN_RESP" | jq -r '.meta.projectId')
META_ISSUED=$(echo "$SIGN_RESP" | jq -r '.meta.issuedFor')
META_EXPIRES=$(echo "$SIGN_RESP" | jq -r '.meta.expiresIn')
META_QR=$(echo "$SIGN_RESP" | jq -r '.meta.quantumResistant')
USAGE_FREE=$(echo "$SIGN_RESP" | jq -r '.usage.freeRemaining')
USAGE_PACK=$(echo "$SIGN_RESP" | jq -r '.usage.packRemaining')
USAGE_TOTAL=$(echo "$SIGN_RESP" | jq -r '.usage.totalRemaining')
USAGE_MONTH=$(echo "$SIGN_RESP" | jq -r '.usage.month')
USER_TOKEN=$(echo "$SIGN_RESP" | jq -c '.token')

if [ "$SIGN_SUCCESS" = "true" ] && [ "$TOKEN_ALG" = "ML-DSA-65" ] && \
   [ "$META_COST" = "1" ] && [ -n "$META_PROJECT" ] && [ -n "$META_ISSUED" ] && \
   [ "$META_EXPIRES" = "3600" ] && [ -n "$USAGE_MONTH" ]; then
  log "algorithm"      "$TOKEN_ALG"
  log "issuedAt"       "$TOKEN_IAT"
  log "tokenCost"      "$META_COST"
  log "source"         "$META_SOURCE"
  log "expiresIn"      "$META_EXPIRES"
  log "quantumResist." "$META_QR"
  log "usage.month"    "$USAGE_MONTH"
  log "freeRemaining"  "$USAGE_FREE"
  log "packRemaining"  "$USAGE_PACK"
  log "totalRemaining" "$USAGE_TOTAL"
  pass "POST /sign user session — correct shape and all fields present"
else
  fail "POST /sign user session" "unexpected response: $SIGN_RESP"
fi

ORDER_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"order_456","amount":1500.00,"currency":"USD","expiresInSeconds":300}')

ORDER_SUCCESS=$(echo "$ORDER_RESP" | jq -r '.success')
ORDER_TOKEN=$(echo "$ORDER_RESP" | jq -c '.token')

if [ "$ORDER_SUCCESS" = "true" ] && [ -n "$ORDER_TOKEN" ]; then
  log "sub"      "order_456"
  log "amount"   "1500"
  log "currency" "USD"
  pass "POST /sign payment order — custom fields accepted"
else
  fail "POST /sign payment order" "unexpected response: $ORDER_RESP"
fi

DOC_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"doc_789","hash":"sha256:abc123","signedBy":"alice"}')

DOC_SUCCESS=$(echo "$DOC_RESP" | jq -r '.success')
DOC_TOKEN=$(echo "$DOC_RESP" | jq -c '.token')

if [ "$DOC_SUCCESS" = "true" ] && [ -n "$DOC_TOKEN" ]; then
  log "sub"      "doc_789"
  log "hash"     "sha256:abc123"
  log "signedBy" "alice"
  pass "POST /sign document — custom fields accepted"
else
  fail "POST /sign document" "unexpected response: $DOC_RESP"
fi

NOSUB_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"email":"test@example.com"}')

NOSUB_SUCCESS=$(echo "$NOSUB_RESP" | jq -r '.success')
NOSUB_ERROR=$(echo "$NOSUB_RESP" | jq -r '.error')

if [ "$NOSUB_SUCCESS" = "false" ] && echo "$NOSUB_ERROR" | grep -q "sub"; then
  log "error" "$NOSUB_ERROR"
  pass "POST /sign missing sub — returns 400 with error"
else
  fail "POST /sign missing sub" "unexpected response: $NOSUB_RESP"
fi

FIELDS_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"test","f1":"a","f2":"b","f3":"c","f4":"d","f5":"e","f6":"f","f7":"g","f8":"h","f9":"i","f10":"j","f11":"k"}')

FIELDS_SUCCESS=$(echo "$FIELDS_RESP" | jq -r '.success')

if [ "$FIELDS_SUCCESS" = "false" ]; then
  log "error" "$(echo "$FIELDS_RESP" | jq -r '.error')"
  pass "POST /sign >10 custom fields — returns 400"
else
  fail "POST /sign >10 custom fields" "should have failed: $FIELDS_RESP"
fi

NOKEY_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -d '{"sub":"user_test"}')

NOKEY_SUCCESS=$(echo "$NOKEY_RESP" | jq -r '.success')

if [ "$NOKEY_SUCCESS" = "false" ]; then
  log "error" "$(echo "$NOKEY_RESP" | jq -r '.error')"
  pass "POST /sign no API key — returns 401"
else
  fail "POST /sign no API key" "should have failed: $NOKEY_RESP"
fi

# ─── 04 Verify ────────────────────────────────────────────────────────────────
section "04 · POST /verify"

VERIFY_RESP=$(api -X POST "$BASE_URL/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $USER_TOKEN}")

VERIFY_VALID=$(echo "$VERIFY_RESP" | jq -r '.valid')
PAYLOAD_SUB=$(echo "$VERIFY_RESP" | jq -r '.payload.sub')
PAYLOAD_ROLE=$(echo "$VERIFY_RESP" | jq -r '.payload.role')
PAYLOAD_IAT=$(echo "$VERIFY_RESP" | jq -r '.payload.iat')
PAYLOAD_EXP=$(echo "$VERIFY_RESP" | jq -r '.payload.exp')

if [ "$VERIFY_VALID" = "true" ] && [ "$PAYLOAD_SUB" = "user_test" ] && \
   [ "$PAYLOAD_ROLE" = "admin" ] && [ -n "$PAYLOAD_IAT" ] && [ -n "$PAYLOAD_EXP" ]; then
  log "valid"  "$VERIFY_VALID"
  log "sub"    "$PAYLOAD_SUB"
  log "role"   "$PAYLOAD_ROLE"
  log "iat"    "$PAYLOAD_IAT"
  log "exp"    "$PAYLOAD_EXP"
  pass "POST /verify valid token — correct payload returned"
else
  fail "POST /verify valid token" "unexpected response: $VERIFY_RESP"
fi

ORDER_VERIFY=$(api -X POST "$BASE_URL/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $ORDER_TOKEN}")

ORDER_VALID=$(echo "$ORDER_VERIFY" | jq -r '.valid')
ORDER_SUB=$(echo "$ORDER_VERIFY" | jq -r '.payload.sub')
ORDER_AMOUNT=$(echo "$ORDER_VERIFY" | jq -r '.payload.amount')

if [ "$ORDER_VALID" = "true" ] && [ "$ORDER_SUB" = "order_456" ] && [ "$ORDER_AMOUNT" = "1500" ]; then
  log "sub"    "$ORDER_SUB"
  log "amount" "$ORDER_AMOUNT"
  pass "POST /verify order token — custom fields preserved in payload"
else
  fail "POST /verify order token" "unexpected response: $ORDER_VERIFY"
fi

TAMPERED_TOKEN=$(echo "$USER_TOKEN" | jq -c '.payload = "TAMPERED_PAYLOAD"')
TAMPERED_RESP=$(api -X POST "$BASE_URL/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $TAMPERED_TOKEN}")

TAMPERED_VALID=$(echo "$TAMPERED_RESP" | jq -r '.valid')
TAMPERED_ERROR=$(echo "$TAMPERED_RESP" | jq -r '.error')

if [ "$TAMPERED_VALID" = "false" ] && [ -n "$TAMPERED_ERROR" ]; then
  log "valid" "$TAMPERED_VALID"
  log "error" "$TAMPERED_ERROR"
  pass "POST /verify tampered token — returns valid:false"
else
  fail "POST /verify tampered token" "unexpected response: $TAMPERED_RESP"
fi

# ─── 05 Revoke ────────────────────────────────────────────────────────────────
section "05 · POST /revoke"

REVOKE_RESP=$(api -X POST "$BASE_URL/revoke" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $DOC_TOKEN, \"reason\": \"integration test\"}")

REVOKE_SUCCESS=$(echo "$REVOKE_RESP" | jq -r '.success')
REVOKE_MSG=$(echo "$REVOKE_RESP" | jq -r '.message')
REVOKE_SUB=$(echo "$REVOKE_RESP" | jq -r '.sub')
REVOKE_AT=$(echo "$REVOKE_RESP" | jq -r '.revokedAt')
REVOKE_EXP=$(echo "$REVOKE_RESP" | jq -r '.expiresAt')
REVOKE_NOTE=$(echo "$REVOKE_RESP" | jq -r '.note')

if [ "$REVOKE_SUCCESS" = "true" ] && [ "$REVOKE_SUB" = "doc_789" ] && \
   [ -n "$REVOKE_AT" ] && [ -n "$REVOKE_EXP" ] && [ -n "$REVOKE_NOTE" ]; then
  log "success"   "$REVOKE_SUCCESS"
  log "message"   "$REVOKE_MSG"
  log "sub"       "$REVOKE_SUB"
  log "revokedAt" "$REVOKE_AT"
  log "expiresAt" "$REVOKE_EXP"
  pass "POST /revoke — token revoked, all fields present"
else
  fail "POST /revoke" "unexpected response: $REVOKE_RESP"
fi

REVOKED_VERIFY=$(api -X POST "$BASE_URL/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $DOC_TOKEN}")

REVOKED_VALID=$(echo "$REVOKED_VERIFY" | jq -r '.valid')
REVOKED_ERROR=$(echo "$REVOKED_VERIFY" | jq -r '.error')

if [ "$REVOKED_VALID" = "false" ] && [ "$REVOKED_ERROR" = "Token has been revoked" ]; then
  log "valid" "$REVOKED_VALID"
  log "error" "$REVOKED_ERROR"
  pass "POST /verify revoked token — returns valid:false with correct error"
else
  fail "POST /verify revoked token" "unexpected response: $REVOKED_VERIFY"
fi

REVOKE2_RESP=$(api -X POST "$BASE_URL/revoke" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $DOC_TOKEN, \"reason\": \"second attempt\"}")

REVOKE2_SUCCESS=$(echo "$REVOKE2_RESP" | jq -r '.success')
REVOKE2_MSG=$(echo "$REVOKE2_RESP" | jq -r '.message')

if [ "$REVOKE2_SUCCESS" = "true" ]; then
  log "message" "$REVOKE2_MSG"
  pass "POST /revoke idempotent — revoking already-revoked token returns success"
else
  fail "POST /revoke idempotent" "unexpected response: $REVOKE2_RESP"
fi

# ─── 06 Expired token ─────────────────────────────────────────────────────────
section "06 · Expired token"

EXP_SIGN=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"expiry_test","expiresInSeconds":1}')

EXP_TOKEN=$(echo "$EXP_SIGN" | jq -c '.token')
EXP_SUCCESS=$(echo "$EXP_SIGN" | jq -r '.success')

if [ "$EXP_SUCCESS" = "true" ]; then
  pass "POST /sign with expiresInSeconds:1 — token created"
else
  fail "POST /sign expiresInSeconds:1" "unexpected response: $EXP_SIGN"
fi

echo -e "  ${DIM}Waiting 2 seconds for token to expire...${RESET}"
sleep 2

EXP_VERIFY=$(api -X POST "$BASE_URL/verify" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $EXP_TOKEN}")

EXP_VALID=$(echo "$EXP_VERIFY" | jq -r '.valid')
EXP_ERROR=$(echo "$EXP_VERIFY" | jq -r '.error')

if [ "$EXP_VALID" = "false" ] && [ -n "$EXP_ERROR" ]; then
  log "valid" "$EXP_VALID"
  log "error" "$EXP_ERROR"
  pass "POST /verify expired token — returns valid:false"
else
  fail "POST /verify expired token" "unexpected response: $EXP_VERIFY"
fi

REVOKE_EXP=$(api -X POST "$BASE_URL/revoke" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"token\": $EXP_TOKEN, \"reason\": \"revoke after expiry\"}")

REVOKE_EXP_SUCCESS=$(echo "$REVOKE_EXP" | jq -r '.success')

if [ "$REVOKE_EXP_SUCCESS" = "false" ]; then
  log "error" "$(echo "$REVOKE_EXP" | jq -r '.error')"
  pass "POST /revoke expired token — returns 400 error"
else
  fail "POST /revoke expired token" "should have failed: $REVOKE_EXP"
fi

# ─── 07 Usage ─────────────────────────────────────────────────────────────────
section "07 · GET /usage"

USAGE_RESP=$(api "$BASE_URL/usage" -H "X-API-Key: $API_KEY")

USAGE_SUCCESS=$(echo "$USAGE_RESP" | jq -r '.success')
USAGE_MONTH_VAL=$(echo "$USAGE_RESP" | jq -r '.current.month')
USAGE_FREE_USED=$(echo "$USAGE_RESP" | jq -r '.current.freeUsed')
USAGE_FREE_REM=$(echo "$USAGE_RESP" | jq -r '.current.freeRemaining')
USAGE_FREE_LIM=$(echo "$USAGE_RESP" | jq -r '.current.freeLimit')
USAGE_PACK_REM=$(echo "$USAGE_RESP" | jq -r '.current.packRemaining')
USAGE_TOTAL_REM=$(echo "$USAGE_RESP" | jq -r '.current.totalRemaining')
USAGE_HISTORY_LEN=$(echo "$USAGE_RESP" | jq '.monthlyHistory | length')
USAGE_NOTE=$(echo "$USAGE_RESP" | jq -r '.note')

if [ "$USAGE_SUCCESS" = "true" ] && [ -n "$USAGE_MONTH_VAL" ] && \
   [ -n "$USAGE_FREE_USED" ] && [ -n "$USAGE_FREE_REM" ] && [ -n "$USAGE_FREE_LIM" ] && \
   [ "$USAGE_HISTORY_LEN" = "6" ] && [ -n "$USAGE_NOTE" ]; then
  log "month"          "$USAGE_MONTH_VAL"
  log "freeUsed"       "$USAGE_FREE_USED"
  log "freeRemaining"  "$USAGE_FREE_REM"
  log "freeLimit"      "$USAGE_FREE_LIM"
  log "packRemaining"  "$USAGE_PACK_REM"
  log "totalRemaining" "$USAGE_TOTAL_REM"
  log "historyMonths"  "$USAGE_HISTORY_LEN"
  pass "GET /usage — correct shape, all fields present, 6-month history"
else
  fail "GET /usage" "unexpected response: $USAGE_RESP"
fi

# ─── 08 Webhooks ──────────────────────────────────────────────────────────────
section "08 · Webhooks"

api -X DELETE "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY" > /dev/null 2>&1 || true

WH_BEFORE=$(api "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY")
WH_BEFORE_NULL=$(echo "$WH_BEFORE" | jq -r '.webhook')

if [ "$WH_BEFORE_NULL" = "null" ]; then
  log "webhook" "null"
  pass "GET /webhooks before register — returns null"
else
  fail "GET /webhooks before register" "webhook should be null: $WH_BEFORE"
fi

WH_REG=$(api -X POST "$BASE_URL/webhooks" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"url\":\"$WEBHOOK_URL\",\"events\":[\"token.signed\",\"limit.warning\"]}")

WH_REG_SUCCESS=$(echo "$WH_REG" | jq -r '.success')
WH_URL=$(echo "$WH_REG" | jq -r '.webhook.url')
WH_SECRET=$(echo "$WH_REG" | jq -r '.webhook.secret')
WH_EVENTS=$(echo "$WH_REG" | jq -r '.webhook.events | join(", ")')

if [ "$WH_REG_SUCCESS" = "true" ] && [ -n "$WH_URL" ] && [ -n "$WH_SECRET" ]; then
  log "url"    "$WH_URL"
  log "events" "$WH_EVENTS"
  log "secret" "${WH_SECRET:0:8}..."
  pass "POST /webhooks — webhook registered with secret"
else
  fail "POST /webhooks" "unexpected response: $WH_REG"
fi

WH_GET=$(api "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY")
WH_GET_URL=$(echo "$WH_GET" | jq -r '.webhook.url')
WH_GET_SECRET=$(echo "$WH_GET" | jq -r '.webhook.secret')
WH_GET_EVENTS=$(echo "$WH_GET" | jq -r '.webhook.events | join(", ")')

if [ -n "$WH_GET_URL" ] && [ "$WH_GET_SECRET" = "null" ]; then
  log "url"    "$WH_GET_URL"
  log "events" "$WH_GET_EVENTS"
  pass "GET /webhooks — returns webhook without secret"
else
  fail "GET /webhooks after register" "unexpected response: $WH_GET"
fi

WH_TEST=$(api -X POST "$BASE_URL/webhooks/test" -H "X-API-Key: $API_KEY")
WH_TEST_SUCCESS=$(echo "$WH_TEST" | jq -r '.success')
WH_TEST_MSG=$(echo "$WH_TEST" | jq -r '.message')

if [ "$WH_TEST_SUCCESS" = "true" ] && [ -n "$WH_TEST_MSG" ]; then
  log "message" "$WH_TEST_MSG"
  pass "POST /webhooks/test — test event dispatched"
else
  fail "POST /webhooks/test" "unexpected response: $WH_TEST"
fi

WH_DEL=$(api -X DELETE "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY")
WH_DEL_SUCCESS=$(echo "$WH_DEL" | jq -r '.success')
WH_AFTER=$(api "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY")
WH_AFTER_NULL=$(echo "$WH_AFTER" | jq -r '.webhook')

if [ "$WH_DEL_SUCCESS" = "true" ] && [ "$WH_AFTER_NULL" = "null" ]; then
  pass "DELETE /webhooks — removed, GET returns null"
else
  fail "DELETE /webhooks" "unexpected state after delete: $WH_AFTER"
fi

# ─── 09 Distinct signatures ───────────────────────────────────────────────────
section "09 · Distinct signatures for identical payloads"

SIG1_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"replay_test","role":"admin","expiresInSeconds":3600}')

# Wait 1 second so iat differs — ML-DSA-65 is deterministic:
# identical message + key = identical signature. Different iat = different payload = different signature.
sleep 1

SIG2_RESP=$(api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"sub":"replay_test","role":"admin","expiresInSeconds":3600}')

SIG1=$(echo "$SIG1_RESP" | jq -r '.token.signature')
SIG2=$(echo "$SIG2_RESP" | jq -r '.token.signature')
PAY1=$(echo "$SIG1_RESP" | jq -r '.token.payload')
PAY2=$(echo "$SIG2_RESP" | jq -r '.token.payload')

if [ "$SIG1" != "$SIG2" ] && [ "$PAY1" != "$PAY2" ]; then
  log "signature1" "${SIG1:0:24}..."
  log "signature2" "${SIG2:0:24}..."
  log "distinct"   "yes ✓"
  pass "signing same payload twice produces distinct signatures — no replay vulnerability"
else
  fail "distinct signatures" "signatures or payloads are identical — possible replay vulnerability"
fi

# ─── 10 Webhook delivery confirmation ─────────────────────────────────────────
section "10 · Webhook delivery confirmation"

api -X DELETE "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY" > /dev/null 2>&1 || true

api -X POST "$BASE_URL/webhooks" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"url\":\"$WEBHOOK_URL\",\"events\":[\"token.signed\"]}" > /dev/null

UNIQUE_SUB="webhook_delivery_test_$(date +%s)"
api -X POST "$BASE_URL/sign" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"sub\":\"$UNIQUE_SUB\",\"expiresInSeconds\":300}" > /dev/null

echo -e "  ${DIM}Waiting 3 seconds for webhook delivery...${RESET}"
sleep 3

WH_SITE_RESP=$(api "https://webhook.site/token/$WEBHOOK_SITE_TOKEN/requests?sorting=newest&per_page=5" \
  -H "Accept: application/json")

WH_SITE_COUNT=$(echo "$WH_SITE_RESP" | jq '.data | length')

if [ "$WH_SITE_COUNT" = "0" ]; then
  fail "webhook delivery confirmation" "no requests received at webhook.site"
else
  FOUND_EVENT=$(echo "$WH_SITE_RESP" | jq -r \
    --arg sub "$UNIQUE_SUB" \
    '.data[] | select(.content != null) | .content | fromjson? | select(.event == "token.signed" and .data.sub == $sub) | .event' \
    2>/dev/null | head -1)

  FOUND_SUB=$(echo "$WH_SITE_RESP" | jq -r \
    --arg sub "$UNIQUE_SUB" \
    '.data[] | select(.content != null) | .content | fromjson? | select(.event == "token.signed" and .data.sub == $sub) | .data.sub' \
    2>/dev/null | head -1)

  if [ "$FOUND_EVENT" = "token.signed" ] && [ "$FOUND_SUB" = "$UNIQUE_SUB" ]; then
    log "event"     "$FOUND_EVENT"
    log "sub"       "$FOUND_SUB"
    log "delivered" "yes ✓"
    pass "webhook delivered and confirmed — event arrived with correct payload"
  else
    fail "webhook delivery confirmation" "event for sub '$UNIQUE_SUB' not found in recent webhook.site requests"
  fi
fi

api -X DELETE "$BASE_URL/webhooks" -H "X-API-Key: $API_KEY" > /dev/null 2>&1 || true

# ─── Summary ──────────────────────────────────────────────────────────────────

TOTAL=$((PASSED + FAILED))
echo ""
echo "────────────────────────────────────────────────"
echo -e "${BOLD}Results: $PASSED/$TOTAL passed${RESET}"

if [ "$FAILED" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}All tests passed. Backend is working correctly.${RESET}"
  echo ""
  exit 0
else
  echo -e "${RED}${BOLD}$FAILED test(s) failed. See above for details.${RESET}"
  echo ""
  exit 1
fi
