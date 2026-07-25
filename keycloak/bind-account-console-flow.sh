#!/usr/bin/env bash
# Binds the browser-google-reauth flow (imported from realm-export.json) to the
# built-in account-console client.
#
# Why this is a script and not part of realm-export.json: Keycloak creates the
# default clients (account, account-console, ...) itself during import, so a
# client entry with clientId=account-console in the export collides with it and
# the whole import fails with "Duplicate resource error".
#
# Without the binding, Account Console -> Signing in -> Set up passkey fails with
# "Cannot login, credential setup required": the application-initiated action
# forces re-authentication, the SSO cookie is bypassed, and browser-passwordless
# has no step that can authenticate a known user who does not have a passkey yet.
#
# Idempotent: safe to re-run.
#
#   ./keycloak/bind-account-console-flow.sh [KEYCLOAK_URL] [REALM] [ADMIN_USER] [ADMIN_PASSWORD]

set -euo pipefail

URL=${1:-http://localhost:8081}
REALM=${2:-kse-pm}
ADMIN_USER=${3:-${KEYCLOAK_ADMIN:-admin}}
ADMIN_PASSWORD=${4:-${KEYCLOAK_ADMIN_PASSWORD:-admin}}
FLOW_ALIAS=browser-google-reauth

token() {
    curl -sf -d "client_id=admin-cli&username=${ADMIN_USER}&password=${ADMIN_PASSWORD}&grant_type=password" \
        "${URL}/realms/master/protocol/openid-connect/token" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

# Wait for the realm import to finish. This script also runs unattended as the
# keycloak-init compose service, which starts the moment the Keycloak container
# does — long before the admin API can mint a token or the realm exists. Without
# the wait, first boot would leave the binding unapplied and passkey enrolment
# broken until someone noticed and re-ran this by hand.
for attempt in $(seq 1 60); do
    if curl -sf -o /dev/null "${URL}/realms/${REALM}/.well-known/openid-configuration"; then
        break
    fi
    if [ "${attempt}" -eq 60 ]; then
        echo "Keycloak realm ${REALM} did not become ready at ${URL} within 5 minutes" >&2
        exit 1
    fi
    sleep 5
done

TOKEN=$(token)
api() { curl -sf -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" "$@"; }

FLOW_ID=$(api "${URL}/admin/realms/${REALM}/authentication/flows" |
    python3 -c "import json,sys; print(next(f['id'] for f in json.load(sys.stdin) if f['alias']=='${FLOW_ALIAS}'))")
CLIENT_ID=$(api "${URL}/admin/realms/${REALM}/clients?clientId=account-console" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')

api -X PUT "${URL}/admin/realms/${REALM}/clients/${CLIENT_ID}" \
    -d "{\"authenticationFlowBindingOverrides\":{\"browser\":\"${FLOW_ID}\"}}"

api "${URL}/admin/realms/${REALM}/clients/${CLIENT_ID}" |
    python3 -c 'import json,sys; c=json.load(sys.stdin); print("account-console browser flow override ->", c["authenticationFlowBindingOverrides"])'
