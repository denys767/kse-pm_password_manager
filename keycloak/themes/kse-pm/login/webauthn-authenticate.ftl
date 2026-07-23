<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayInfo=false; section>
<!-- Custom passkey page: explicit Google alternative for the WebAuthn flow. -->
    <#if section = "title">
        ${msg("loginAccountTitle")}
    <#elseif section = "header">
        ${kcSanitize(msg("loginAccountTitle"))?no_esc}
    <#elseif section = "form">
        <div id="kc-form-webauthn" class="${properties.kcFormClass!}">
            <form id="webauth" action="${url.loginAction}" method="post" hidden="hidden">
                <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
                <input type="hidden" id="authenticatorData" name="authenticatorData"/>
                <input type="hidden" id="signature" name="signature"/>
                <input type="hidden" id="credentialId" name="credentialId"/>
                <input type="hidden" id="userHandle" name="userHandle"/>
                <input type="hidden" id="error" name="error"/>
            </form>

            <#-- Google first and primary: a passkey is optional, so on any given visit
                 most users (and every brand-new one) have no credential to present. The
                 passkey button below is deliberately secondary — clicking it with no
                 registered passkey only produces a browser-level "no credentials" prompt,
                 which must not be the default path.
                 Must use social.providers' own loginUrl (a direct broker redirect), not
                 url.loginAction + kc_idp_hint: that URL belongs to this page's WebAuthn
                 execution, so a GET to it re-enters WebAuthn's action() expecting a
                 signed assertion and fails with "invalid_user_credentials" instead of
                 redirecting to Google.
                 keycloak.v2 ships no icon font, so a background-image substitutes for the
                 "fa fa-google" glyph the legacy theme would auto-resolve via kcLogoIdP-google. -->
            <#if social?? && social.providers?? && social.providers?has_content>
            <div id="kc-social-providers">
                <#list social.providers as p>
                <@buttons.actionGroup>
                    <a id="social-${p.alias}" class="${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} kc-idp-button" href="${p.loginUrl}">
                        <#if p.alias == "google"><span class="kc-idp-icon-google" aria-hidden="true"></span></#if>
                        <span>Sign in with ${p.displayName!}</span>
                    </a>
                </@buttons.actionGroup>
                </#list>
            </div>
            </#if>

            <@buttons.actionGroup>
                <button id="authenticateWebAuthnButton" type="button" class="${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}">Sign in with Passkey</button>
            </@buttons.actionGroup>
            <p class="kc-passkey-hint">A passkey is optional. You can add one later in the Account Console.</p>

            <#-- Flex layout for this button lives in the theme's login.css: it has to
                 out-specify PatternFly's .pf-v5-c-button.pf-m-block to apply at all. -->
            <style>
                .kc-passkey-hint {
                    margin: 8px 0 0; text-align: center; font-size: 12px; opacity: .7;
                }
                .kc-idp-icon-google {
                    display: inline-block; width: 18px; height: 18px; flex: none;
                    background-image: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxOCIgaGVpZ2h0PSIxOCIgdmlld0JveD0iMCAwIDE4IDE4Ij48cGF0aCBmaWxsPSIjNDI4NUY0IiBkPSJNMTcuNjQgOS4yYzAtLjY0LS4wNi0xLjI1LS4xNi0xLjg0SDl2My40OGg0Ljg0YTQuMTQgNC4xNCAwIDAgMS0xLjggMi43MnYyLjI2aDIuOWMxLjctMS41NyAyLjctMy44OCAyLjctNi42MnoiLz48cGF0aCBmaWxsPSIjMzRBODUzIiBkPSJNOSAxOGMyLjQzIDAgNC40Ny0uOCA1Ljk2LTIuMThsLTIuOS0yLjI2Yy0uOC41NC0xLjg0Ljg2LTMuMDYuODYtMi4zNSAwLTQuMzQtMS41OS01LjA1LTMuNzJILjk1djIuMzNBOSA5IDAgMCAwIDkgMTh6Ii8+PHBhdGggZmlsbD0iI0ZCQkMwNSIgZD0iTTMuOTUgMTAuN0E1LjQgNS40IDAgMCAxIDMuNjcgOWMwLS41OS4xLTEuMTcuMjgtMS43VjQuOTdILjk1QTkgOSAwIDAgMCAwIDljMCAxLjQ1LjM1IDIuODMuOTUgNC4wM2wzLTIuMzN6Ii8+PHBhdGggZmlsbD0iI0VBNDMzNSIgZD0iTTkgMy41OGMxLjMyIDAgMi41LjQ1IDMuNDQgMS4zNWwyLjU4LTIuNThDMTMuNDYuODkgMTEuNDMgMCA5IDBBOSA5IDAgMCAwIC45NSA0Ljk3bDMgMi4zM0M0LjY2IDUuMTcgNi42NSAzLjU4IDkgMy41OHoiLz48L3N2Zz4=");
                    background-size: contain; background-repeat: no-repeat; background-position: center;
                }
            </style>
        </div>
        <script type="module">
            import { authenticateByWebAuthn } from "${url.resourcesPath}/js/webauthnAuthenticate.js";
            document.getElementById("authenticateWebAuthnButton").addEventListener("click", function() {
                authenticateByWebAuthn({
                    isUserIdentified: ${isUserIdentified},
                    challenge: '${challenge}',
                    userVerification: '${userVerification}',
                    rpId: '${rpId}',
                    createTimeout: ${createTimeout?c},
                    errmsg: "${msg("webauthn-unsupported-browser-text")?no_esc}"
                });
            }, { once: true });
        </script>
    </#if>
</@layout.registrationLayout>
