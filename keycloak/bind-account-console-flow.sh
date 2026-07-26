#!/usr/bin/env bash
# Post-import realm configuration that cannot live in realm-export.json:
#
#   1. binds the browser-google-reauth flow to the built-in account-console
#      client;
#   2. makes email/username/first/last name read-only for the user, so Account
#      Console only offers passkey management;
#   3. switches the first-broker-login profile review off (the other screen
#      where a user could set their own email);
#   4. checks that an identity provider is still offered on the login page.
#
# Steps 2-4 are applied over the Admin API on every start because a realm
# import never updates a realm that already exists.
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

# --- Identity attributes are read-only for the user -------------------------
# Account Console → Personal info renders (and the Account REST API accepts)
# exactly what the declarative user profile allows. Identity comes from Google
# Workspace and this application's authorization is keyed on the email address,
# so a self-service email change would detach the account from its vault
# records. Passkeys live under Account security and are untouched.
#
# The profile is patched in place rather than replaced: only the `edit`
# permission of the four identity attributes changes, so every validator,
# annotation and custom attribute this Keycloak version ships keeps working.
PROFILE=$(api "${URL}/admin/realms/${REALM}/users/profile")
LOCKED=$(PROFILE_JSON="${PROFILE}" python3 -c '
import json, os, sys
profile = json.loads(os.environ["PROFILE_JSON"])
for attribute in profile.get("attributes", []):
    if attribute.get("name") not in ("username", "email", "firstName", "lastName"):
        continue
    permissions = attribute.setdefault("permissions", {})
    view = permissions.get("view") or []
    # Keep the field visible; the Account Console then shows it read-only.
    permissions["view"] = sorted(set(view) | {"admin", "user"})
    permissions["edit"] = ["admin"]
sys.stdout.write(json.dumps(profile))')
api -X PUT "${URL}/admin/realms/${REALM}/users/profile" -d "${LOCKED}" >/dev/null

api "${URL}/admin/realms/${REALM}/users/profile" |
    python3 -c 'import json,sys; print("user profile edit permissions ->", {a["name"]: a.get("permissions",{}).get("edit") for a in json.load(sys.stdin)["attributes"]})'

# --- No self-service profile review on first Google login -------------------
# "missing" (the default) shows a prefilled Update Account Information form on
# first broker login, which is a user-controlled email field regardless of the
# permissions above.
EXECUTIONS=$(api "${URL}/admin/realms/${REALM}/authentication/flows/first%20broker%20login/executions" || echo "[]")
REVIEW=$(EXECUTIONS_JSON="${EXECUTIONS}" python3 -c 'import json, os
review = [e for e in json.loads(os.environ["EXECUTIONS_JSON"]) if e.get("providerId") == "idp-review-profile"]
print(review[0]["id"], review[0].get("authenticationConfig", "")) if review else print()')
read -r REVIEW_EXECUTION REVIEW_CONFIG <<<"${REVIEW}"
if [ -z "${REVIEW_EXECUTION:-}" ]; then
    echo "first broker login has no idp-review-profile step; nothing to switch off"
elif [ -n "${REVIEW_CONFIG:-}" ]; then
    api -X PUT "${URL}/admin/realms/${REALM}/authentication/config/${REVIEW_CONFIG}" \
        -d '{"alias":"review profile config","config":{"update.profile.on.first.login":"off"}}'
    echo "first broker login profile review -> off"
else
    api -X POST "${URL}/admin/realms/${REALM}/authentication/executions/${REVIEW_EXECUTION}/config" \
        -d '{"alias":"review profile config","config":{"update.profile.on.first.login":"off"}}' >/dev/null
    echo "first broker login profile review -> off (config created)"
fi

# --- Guard: the SSO button must still be on the login page ------------------
# Locking the profile must never cost users their only way in. If an identity
# provider is disabled or hidden, say so loudly: without this the failure looks
# like "the login page only offers a passkey".
api "${URL}/admin/realms/${REALM}/identity-provider/instances" | python3 -c '
import json, sys
providers = json.load(sys.stdin)
usable = [p for p in providers if p.get("enabled") and not p.get("hideOnLogin")]
print("identity providers on the login page ->", [p["alias"] for p in usable] or "NONE")
if providers and not usable:
    sys.exit("ERROR: every identity provider is disabled or hidden; the login page would offer passkeys only")'
