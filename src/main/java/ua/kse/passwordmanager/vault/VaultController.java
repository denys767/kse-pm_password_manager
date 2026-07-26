package ua.kse.passwordmanager.vault;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.attachment.AttachmentMetadataResponse;
import ua.kse.passwordmanager.attachment.AttachmentService;

@RestController
@RequestMapping("/api/vault/items")
public class VaultController {

    private final VaultService vaultService;
    private final AuthFacade authFacade;
    private final AttachmentService attachments;

    public VaultController(VaultService vaultService, AuthFacade authFacade, AttachmentService attachments) {
        this.vaultService = vaultService;
        this.authFacade = authFacade;
        this.attachments = attachments;
    }

    @GetMapping
    public List<PasswordItemResponse> list() {
        return vaultService.list(authFacade.current(), authFacade.isExtensionClient());
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PasswordItemResponse create(@Valid @RequestBody PasswordItemRequest request) {
        return vaultService.create(authFacade.current(), request);
    }

    @GetMapping("/{id}")
    public PasswordItemResponse get(@PathVariable UUID id) {
        return vaultService.get(authFacade.current(), id, authFacade.isExtensionClient());
    }

    @PutMapping("/{id}")
    public PasswordItemResponse update(@PathVariable UUID id,
                                       @Valid @RequestBody PasswordItemRequest request) {
        return vaultService.update(authFacade.current(), id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        vaultService.delete(authFacade.current(), id);
    }

    /** Previous versions of the item (ciphertext under the same item key). */
    @GetMapping("/{id}/versions")
    public List<ItemVersionResponse> versions(@PathVariable UUID id) {
        return vaultService.versions(authFacade.current(), id);
    }

    /** Client-reported clipboard copy, recorded for the audit trail. */
    @PostMapping("/{id}/copy-event")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void copyEvent(@PathVariable UUID id) {
        vaultService.recordCopy(authFacade.current(), id);
    }

    @PatchMapping("/{id}/sync-mode")
    public PasswordItemResponse changeSyncMode(@PathVariable UUID id,
                                               @Valid @RequestBody SyncModeRequest request) {
        return vaultService.changeSyncMode(authFacade.current(), id, request.syncMode());
    }

    /** Move the item into / out of a collection (owner only). */
    @PutMapping("/{id}/collection")
    public PasswordItemResponse changeCollection(@PathVariable UUID id,
                                                 @Valid @RequestBody ItemCollectionRequest request) {
        return vaultService.changeCollection(authFacade.current(), id, request);
    }

    /** Rotate the item's AES key, typically as part of revoking a share. */
    @PostMapping("/{id}/rotate-key")
    public PasswordItemResponse rotateKey(@PathVariable UUID id,
                                          @Valid @RequestBody RotateKeyRequest request) {
        return vaultService.rotateKey(authFacade.current(), id, request);
    }

    @PutMapping(value = "/{id}/attachment", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public AttachmentMetadataResponse uploadAttachment(@PathVariable UUID id,
            @RequestHeader("X-Kse-Attachment-Metadata") String metadata, HttpServletRequest request) throws IOException {
        return attachments.upload(authFacade.current(), id, metadata, request.getInputStream());
    }

    @GetMapping("/{id}/attachment")
    public AttachmentMetadataResponse attachmentMetadata(@PathVariable UUID id) {
        return attachments.metadata(authFacade.current(), id, authFacade.isExtensionClient());
    }

    @GetMapping(value = "/{id}/attachment/content", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<StreamingResponseBody> downloadAttachment(@PathVariable UUID id) {
        var user = authFacade.current();
        boolean extensionClient = authFacade.isExtensionClient();
        long size = attachments.metadata(user, id, extensionClient).ciphertextSize();
        StreamingResponseBody body = out -> attachments.download(user, id, out, extensionClient);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_LENGTH, Long.toString(size))
                .body(body);
    }

    @DeleteMapping("/{id}/attachment")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteAttachment(@PathVariable UUID id) { attachments.delete(authFacade.current(), id); }
}
