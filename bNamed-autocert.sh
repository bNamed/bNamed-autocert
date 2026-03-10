#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Defaults
# -----------------------------
CONFIG_FILE_DEFAULT="/etc/bNamed-autocert.conf"

API_URL="https://api.bNamed.net/API"
APIUID=""
APIKEY=""

CN=""
PRIVKEY_PATH=""
FULLCHAIN_PATH=""
COMBINED_PEM_PATH=""

CERTTYPE="PositiveSSL"
AUTOPAY="true"

MAX_POLLS=20
POLL_INTERVAL=60

usage() {
  cat <<'EOF'
Usage:
  bNamed-autocert.sh [--config /path/file.conf]
    [--api-url URL] [--apiuid UID] [--apikey KEY]
    --cn "CN"
    --privkey /path/privkey.pem
    --fullchain /path/fullchain.pem
    [--certtype TYPE] [--autopay true|false]
    [--max-polls N] [--poll-interval SEC]

Notes:
- Values can come from a config file or CLI.
- CLI options override config values.
- Default config file: /etc/bNamed-autocert.conf

Example:
  ./bNamed-autocert.sh --config ./bNamed-autocert.conf \
    --cn "*.nameweb.biz" \
    --privkey /etc/nginx/ssl/nameweb.biz/privkey.pem \
    --fullchain /etc/nginx/ssl/nameweb.biz/fullchain.pem
  # Optional combined PEM (key + chain in one file):
  # --combined-pem /etc/nginx/ssl/bn.md.pem

EOF
}

# =============================
# 1) Parse only --config first
# =============================
CONFIG_FILE="$CONFIG_FILE_DEFAULT"
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done
set -- "${args[@]}"

# =============================
# 2) Load config file (if present)
# =============================
load_config() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  # shellcheck disable=SC1090
  source "$f"
}

load_config "$CONFIG_FILE"

# =============================
# 3) Parse CLI options (override config)
# =============================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url)       API_URL="$2"; shift 2 ;;
    --apiuid)        APIUID="$2"; shift 2 ;;
    --apikey)        APIKEY="$2"; shift 2 ;;

    --cn)            CN="$2"; shift 2 ;;
    --privkey)       PRIVKEY_PATH="$2"; shift 2 ;;
    --fullchain)     FULLCHAIN_PATH="$2"; shift 2 ;;
    --combined-pem)  COMBINED_PEM_PATH="$2"; shift 2 ;;

    --certtype)      CERTTYPE="$2"; shift 2 ;;
    --autopay)       AUTOPAY="$2"; shift 2 ;;

    --max-polls)     MAX_POLLS="$2"; shift 2 ;;
    --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;

    -h|--help)       usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# =============================
# 4) Validation
# =============================
command -v curl >/dev/null 2>&1    || { echo "ERROR: curl is required"; exit 1; }
command -v xmllint >/dev/null 2>&1 || { echo "ERROR: xmllint is required (libxml2-utils)"; exit 1; }

if [[ -z "$APIUID" || -z "$APIKEY" ]]; then
  echo "ERROR: APIUID and APIKEY must be set (config or CLI)." >&2
  exit 2
fi

if [[ -z "$CN" ]]; then
  echo "ERROR: --cn (CN) must be set (config or CLI)." >&2
  exit 2
fi

if [[ -z "$PRIVKEY_PATH" && -z "$FULLCHAIN_PATH" && -z "$COMBINED_PEM_PATH" ]]; then
  echo "ERROR: You must configure at least one of: PRIVKEY_PATH, FULLCHAIN_PATH, COMBINED_PEM_PATH." >&2
  exit 2
fi

# =============================
# 5) Temp dir & common vars
# =============================
umask 077
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

tmp_priv="$TMPDIR/privkey.pem"
tmp_chain="$TMPDIR/fullchain.pem"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

# Helper to clean PEM (remove CR, remove empty/whitespace-only lines)
clean_pem() {
  sed -e 's/\r$//' -e '/^[[:space:]]*$/d'
}

# =============================
# 6) requestAutoCert (with one retry on 19901)
# =============================
request_autocert() {
  curl -fsS --get "$API_URL" \
    --data-urlencode "UID=${APIUID}" \
    --data-urlencode "key=${APIKEY}" \
    --data-urlencode "command=requestAutoCert" \
    --data-urlencode "CN=${CN}" \
    --data-urlencode "CertType=${CERTTYPE}" \
    --data-urlencode "autopay=${AUTOPAY}"
}

echo "Requesting certificate for CN=${CN} (type=${CERTTYPE}) ..."

# First attempt
REQ_XML="$(request_autocert)"
ERRORCODE="$(xmllint --xpath 'string(/API/ErrorCode)' - <<<"$REQ_XML")"

if [[ "$ERRORCODE" == "19901" ]]; then
  echo "INFO: Another request already pending (ErrorCode=19901). Sleeping 10 minutes before one retry..." >&2
  sleep $((10 * 60))

  # Second attempt
  REQ_XML="$(request_autocert)"
  ERRORCODE="$(xmllint --xpath 'string(/API/ErrorCode)' - <<<"$REQ_XML")"
fi

if [[ "$ERRORCODE" != "0" ]]; then
  ERRORTEXT="$(xmllint --xpath 'string(/API/ErrorText)' - <<<"$REQ_XML" 2>/dev/null || true)"
  echo "ERROR: requestAutoCert failed: ErrorCode=$ERRORCODE $ERRORTEXT" >&2
  exit 1
fi

REQUEST_ID="$(xmllint --xpath 'string(/API/Result/Request-ID)' - <<<"$REQ_XML")"
if [[ -z "$REQUEST_ID" ]]; then
  echo "ERROR: Could not parse Request-ID from requestAutoCert response" >&2
  exit 1
fi
echo "Request-ID: $REQUEST_ID"

# Write private key to temp file, cleaning bad blank lines
xmllint --xpath 'string(/API/Result/PK)' - <<<"$REQ_XML" \
  | clean_pem > "$tmp_priv"

if ! grep -q '^-----BEGIN .*PRIVATE KEY-----' "$tmp_priv"; then
  echo "ERROR: Private key does not look like PEM" >&2
  exit 1
fi

# Optional: parse check with OpenSSL if available
if command -v openssl >/dev/null 2>&1; then
  if ! openssl pkey -noout -in "$tmp_priv" >/dev/null 2>&1; then
    echo "ERROR: Private key is not parseable by OpenSSL" >&2
    exit 1
  fi
fi

# =============================
# 7) Poll getAutoCert until completed
# =============================
status="unknown"

for ((i=1; i<=MAX_POLLS; i++)); do
  GET_XML="$(
    curl -fsS --get "$API_URL" \
      --data-urlencode "UID=${APIUID}" \
      --data-urlencode "key=${APIKEY}" \
      --data-urlencode "command=getAutoCert" \
      --data-urlencode "request-id=${REQUEST_ID}"
  )"

  ERRORCODE="$(xmllint --xpath 'string(/API/ErrorCode)' - <<<"$GET_XML")"
  if [[ "$ERRORCODE" != "0" ]]; then
    ERRORTEXT="$(xmllint --xpath 'string(/API/ErrorText)' - <<<"$GET_XML" 2>/dev/null || true)"
    echo "ERROR: getAutoCert failed: ErrorCode=$ERRORCODE $ERRORTEXT" >&2
    exit 1
  fi

  status="$(xmllint --xpath 'string(/API/Result/status)' - <<<"$GET_XML" 2>/dev/null || true)"
  [[ -n "$status" ]] || status="unknown"

  echo "[$i/$MAX_POLLS] status=$status"

  if [[ "$status" == "completed" ]]; then
    xmllint --xpath 'string(/API/Result/pem-certificate-chain)' - <<<"$GET_XML" \
      | clean_pem > "$tmp_chain"
    break
  fi

  sleep "$POLL_INTERVAL"
done

if [[ "$status" != "completed" ]]; then
  echo "ERROR: Timed out waiting for certificate (last status=$status)" >&2
  exit 1
fi

if ! grep -q '^-----BEGIN CERTIFICATE-----' "$tmp_chain"; then
  echo "ERROR: Certificate chain does not look like PEM" >&2
  exit 1
fi

if command -v openssl >/dev/null 2>&1; then
  if ! openssl x509 -noout -in "$tmp_chain" >/dev/null 2>&1; then
    echo "ERROR: Certificate chain is not parseable by OpenSSL" >&2
    exit 1
  fi
fi

# =============================
# 8) Backup existing files & install new ones
# =============================
# Make directories for outputs that are actually used
[[ -n "$PRIVKEY_PATH" ]]       && mkdir -p "$(dirname "$PRIVKEY_PATH")"
[[ -n "$FULLCHAIN_PATH" ]]     && mkdir -p "$(dirname "$FULLCHAIN_PATH")"
[[ -n "$COMBINED_PEM_PATH" ]]  && mkdir -p "$(dirname "$COMBINED_PEM_PATH")"

# Backup existing files
if [[ -n "$PRIVKEY_PATH" && -e "$PRIVKEY_PATH" ]]; then
  cp -a -- "$PRIVKEY_PATH" "${PRIVKEY_PATH}.${timestamp}.bak"
fi
if [[ -n "$FULLCHAIN_PATH" && -e "$FULLCHAIN_PATH" ]]; then
  cp -a -- "$FULLCHAIN_PATH" "${FULLCHAIN_PATH}.${timestamp}.bak"
fi
if [[ -n "$COMBINED_PEM_PATH" && -e "$COMBINED_PEM_PATH" ]]; then
  cp -a -- "$COMBINED_PEM_PATH" "${COMBINED_PEM_PATH}.${timestamp}.bak"
fi

# Install separate files (if configured)
if [[ -n "$PRIVKEY_PATH" ]]; then
  install -m 600 "$tmp_priv" "$PRIVKEY_PATH"
fi
if [[ -n "$FULLCHAIN_PATH" ]]; then
  install -m 644 "$tmp_chain" "$FULLCHAIN_PATH"
fi

# Install combined PEM (key + chain) if requested
if [[ -n "$COMBINED_PEM_PATH" ]]; then
  tmp_combined="$TMPDIR/combined.pem"
  {
    cat "$tmp_priv"
    echo
    cat "$tmp_chain"
  } > "$tmp_combined"
  install -m 600 "$tmp_combined" "$COMBINED_PEM_PATH"
fi

echo "OK. Updated:"
[[ -n "$PRIVKEY_PATH" ]]       && echo "  $PRIVKEY_PATH"
[[ -n "$FULLCHAIN_PATH" ]]     && echo "  $FULLCHAIN_PATH"
[[ -n "$COMBINED_PEM_PATH" ]]  && echo "  $COMBINED_PEM_PATH"
echo "Backups (if any): *.${timestamp}.bak"
