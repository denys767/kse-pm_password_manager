#!/usr/bin/env bash
# One-time GCP setup for keyless Google Workspace credentials (workload
# identity federation). After this runs, the backend authenticates to Keycloak
# with a client_credentials machine grant and exchanges that token at Google
# STS — no downloaded service-account key, and nothing in the chain that a
# human has to re-authenticate. See docs/DEPLOYMENT.md, "Mode A".
#
# Needs: gcloud (authenticated as someone with IAM admin on the project),
# curl, python3, and a running Keycloak whose kse-pm realm has already been
# imported (the kse-pm-federation client comes from keycloak/realm-export.json).
#
# Idempotent: safe to re-run. Existing pool/provider/binding are left alone.
#
#   ./scripts/setup-workload-identity.sh
#
# Configure by environment (see the two ready-made blocks at the bottom of
# this file for local vs production).

set -euo pipefail

# ---------------------------------------------------------------- configuration
# Google Cloud project that owns the target service account.
GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT (e.g. kse-pm-prod)}"
# The service account that already has domain-wide delegation authorized in the
# Workspace Admin Console. Same value as GOOGLE_WORKSPACE_SERVICE_ACCOUNT_EMAIL.
TARGET_SA="${TARGET_SA:?set TARGET_SA (e.g. directory-sync@<project>.iam.gserviceaccount.com)}"

# Base URL of Keycloak *as the backend reaches it* and as it stamps `iss` into
# tokens. This is the value that matters: Google compares the token's `iss`
# claim against the provider's issuer URI, so it must match exactly.
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8081}"
REALM="${REALM:-kse-pm}"
FEDERATION_CLIENT_ID="${FEDERATION_CLIENT_ID:-kse-pm-federation}"
FEDERATION_CLIENT_SECRET="${WORKSPACE_FEDERATION_CLIENT_SECRET:?set WORKSPACE_FEDERATION_CLIENT_SECRET (must match the Keycloak client secret)}"

POOL="${POOL:-kse-pm}"
PROVIDER="${PROVIDER:-keycloak}"

# Reachability of the issuer decides how Google validates Keycloak's tokens:
#   discovery  — Google fetches ${ISSUER}/.well-known/openid-configuration and
#                the JWKS itself. Requires a public HTTPS URL with a publicly
#                trusted certificate. Use this in production.
#   jwks       — the realm's public keys are uploaded inline, so Google never
#                calls Keycloak. Use this when Keycloak is not publicly
#                reachable. Must be re-run whenever the realm's signing keys
#                rotate.
# Defaults to jwks for a localhost issuer, discovery otherwise.
if [[ -z "${ISSUER_MODE:-}" ]]; then
  if [[ "$KEYCLOAK_URL" == *localhost* || "$KEYCLOAK_URL" == *127.0.0.1* ]]; then
    ISSUER_MODE=jwks
  else
    ISSUER_MODE=discovery
  fi
fi

ISSUER="${KEYCLOAK_URL}/realms/${REALM}"
TOKEN_URL="${ISSUER}/protocol/openid-connect/token"

echo "==> project=${GCP_PROJECT} sa=${TARGET_SA}"
echo "==> issuer=${ISSUER} (mode: ${ISSUER_MODE})"

if [[ "$ISSUER_MODE" == "discovery" && "$ISSUER" != https://* ]]; then
  echo "ERROR: discovery mode needs an https issuer that Google can reach." >&2
  echo "       Set ISSUER_MODE=jwks, or point KEYCLOAK_URL at the public HTTPS host." >&2
  exit 1
fi

PROJECT_NUMBER="$(gcloud projects describe "$GCP_PROJECT" --format='value(projectNumber)')"
AUDIENCE="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"
PRINCIPAL_PREFIX="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/subject"

# ------------------------------------------------------------------- 1. the pool
if gcloud iam workload-identity-pools describe "$POOL" \
     --project="$GCP_PROJECT" --location=global >/dev/null 2>&1; then
  echo "==> pool ${POOL} already exists"
else
  echo "==> creating pool ${POOL}"
  gcloud iam workload-identity-pools create "$POOL" \
    --project="$GCP_PROJECT" --location=global \
    --display-name="KSE Password Manager"
fi

# --------------------------------------------------------------- 2. the provider
# The kse-pm-federation client stamps the audience below into the token's `aud`
# via its google-sts-audience mapper, which is exactly what Google STS expects,
# so no --allowed-audiences override is needed here.
if gcloud iam workload-identity-pools providers describe "$PROVIDER" \
     --project="$GCP_PROJECT" --location=global \
     --workload-identity-pool="$POOL" >/dev/null 2>&1; then
  echo "==> provider ${PROVIDER} already exists (delete it to change issuer/JWKS)"
else
  echo "==> creating OIDC provider ${PROVIDER}"
  if [[ "$ISSUER_MODE" == "jwks" ]]; then
    JWKS_FILE="$(mktemp)"
    trap 'rm -f "$JWKS_FILE"' EXIT
    curl -fsS "${ISSUER}/protocol/openid-connect/certs" -o "$JWKS_FILE"
    echo "    uploaded realm JWKS ($(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["keys"]))' "$JWKS_FILE") keys)"
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
      --project="$GCP_PROJECT" --location=global \
      --workload-identity-pool="$POOL" \
      --issuer-uri="$ISSUER" \
      --jwk-json-path="$JWKS_FILE" \
      --attribute-mapping=google.subject=assertion.sub
  else
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
      --project="$GCP_PROJECT" --location=global \
      --workload-identity-pool="$POOL" \
      --issuer-uri="$ISSUER" \
      --attribute-mapping=google.subject=assertion.sub
  fi
fi

# ------------------------------------------- 3. the Keycloak service account sub
# The IAM binding names the caller by the token's `sub` claim, which is a
# Keycloak user UUID. Read it from a real token rather than guessing — this
# also proves the client secret and the grant actually work.
echo "==> requesting a client_credentials token from ${TOKEN_URL}"
ACCESS_TOKEN="$(curl -fsS -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d "client_id=${FEDERATION_CLIENT_ID}" \
  -d "client_secret=${FEDERATION_CLIENT_SECRET}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')"

read -r SUB TOKEN_AUD <<<"$(python3 - "$ACCESS_TOKEN" <<'PY'
import base64, json, sys
payload = sys.argv[1].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
aud = claims.get("aud", "")
print(claims["sub"], ",".join(aud) if isinstance(aud, list) else aud)
PY
)"
echo "==> keycloak service account sub=${SUB}"

# The audience mapper is what makes STS accept the token. Catch a mismatch here
# rather than as an opaque STS rejection at runtime.
if [[ ",${TOKEN_AUD}," != *",${AUDIENCE},"* ]]; then
  echo "WARNING: the token's aud (${TOKEN_AUD}) does not contain" >&2
  echo "         ${AUDIENCE}" >&2
  echo "         Set WORKSPACE_FEDERATION_AUDIENCE to that value in the Keycloak" >&2
  echo "         container's environment and restart it, then re-run this script." >&2
fi

# ------------------------------------------------------------- 4. the IAM binding
echo "==> granting roles/iam.serviceAccountTokenCreator on ${TARGET_SA}"
gcloud iam service-accounts add-iam-policy-binding "$TARGET_SA" \
  --project="$GCP_PROJECT" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --member="${PRINCIPAL_PREFIX}/${SUB}" >/dev/null

# ------------------------------------------------------------------- 5. the env
cat <<EOF

==> Done. Put these in the backend's environment (and leave
    GOOGLE_WORKSPACE_CREDENTIALS_PATH empty so federation takes effect):

WORKSPACE_FEDERATION_TOKEN_URL=${TOKEN_URL}
WORKSPACE_FEDERATION_CLIENT_ID=${FEDERATION_CLIENT_ID}
WORKSPACE_FEDERATION_CLIENT_SECRET=<the Keycloak client secret>
WORKSPACE_FEDERATION_AUDIENCE=${AUDIENCE}

    Keycloak also needs WORKSPACE_FEDERATION_AUDIENCE and
    WORKSPACE_FEDERATION_CLIENT_SECRET in its own environment (the realm
    import substitutes them into the ${FEDERATION_CLIENT_ID} client).

    Verify after restart:
      GET /api/admin/workspace/directory-status
      -> credentialMode: workload-identity-federation
         credentialUnattended: true
         credentialLastError: null
EOF
