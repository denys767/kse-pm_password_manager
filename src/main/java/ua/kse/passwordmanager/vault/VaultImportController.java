package ua.kse.passwordmanager.vault;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;

/** Two-phase encrypted import: preview is read-only and commit is one DB
 * transaction. Attachments are intentionally excluded until Drive staging is
 * available; callers must not send plaintext file content to this API. */
@RestController
@RequestMapping("/api/vault/imports")
public class VaultImportController {
    private final VaultService vault;
    private final AuthFacade auth;

    public VaultImportController(VaultService vault, AuthFacade auth) {
        this.vault = vault;
        this.auth = auth;
    }

    @PostMapping("/preview")
    public VaultImportPreview preview(@Valid @RequestBody VaultImportBatchRequest request) {
        return vault.previewImport(auth.current(), request);
    }

    @PostMapping("/commit")
    public VaultImportPreview commit(@Valid @RequestBody VaultImportBatchRequest request) {
        return vault.importBatch(auth.current(), request);
    }
}
