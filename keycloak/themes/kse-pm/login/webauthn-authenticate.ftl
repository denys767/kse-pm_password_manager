<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayInfo=false; section>
<!-- Custom passkey page: explicit Google alternative for the WebAuthn flow. -->
    <#if section = "title">
        ${msg("webauthn-login-title")}
    <#elseif section = "header">
        ${kcSanitize(msg("webauthn-login-title"))?no_esc}
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

            <@buttons.actionGroup>
                <@buttons.button id="authenticateWebAuthnButton" label="webauthn-doAuthenticate" class=["kcButtonPrimaryClass", "kcButtonBlockClass"]/>
            </@buttons.actionGroup>

            <div class="${properties.kcLoginMainFooterBand!}">
                <span class="${properties.kcLoginMainFooterBandItem!} ${properties.kcLoginMainFooterHelperText!}">or</span>
            </div>
            <div id="kc-social-providers" class="${properties.kcFormSocialAccountSectionClass!}">
                <a id="social-google" class="${properties.kcFormSocialAccountListButtonClass!}" href="${url.loginAction}&amp;kc_idp_hint=google">
                    <span class="${properties.kcFormSocialAccountNameClass!}">Sign in with Google</span>
                </a>
            </div>
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
