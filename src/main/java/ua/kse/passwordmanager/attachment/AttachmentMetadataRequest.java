package ua.kse.passwordmanager.attachment;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

/** Metadata is opaque encrypted material except the MIME type and byte count. */
public record AttachmentMetadataRequest(
        @NotBlank @Size(max = 4096) String encryptedFilename,
        @NotBlank @Size(max = 255) String encryptedFilenameIv,
        @NotBlank @Size(max = 255) String mimeType,
        @NotNull @PositiveOrZero Long ciphertextSize,
        @NotBlank @Pattern(regexp = "[0-9a-fA-F]{64}") String ciphertextSha256,
        @NotBlank @Size(max = 255) String nonce,
        @NotBlank @Size(max = 4096) String wrappedFileKey,
        @NotBlank @Size(max = 255) String wrappedFileKeyIv) {
}
