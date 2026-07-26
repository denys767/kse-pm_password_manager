package ua.kse.passwordmanager.attachment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.common.QuotaExceededException;
import ua.kse.passwordmanager.google.DelegatedTokenMinter;

/** Google Drive appDataFolder transport using domain-wide delegation to the
 * record owner. Resumable upload is streamed in fixed-size chunks and download
 * is streamed straight to the response, so a large attachment costs bounded
 * heap rather than one full in-memory copy per concurrent request — there is
 * no separate application-level size policy; Drive/Workspace quotas are the
 * authoritative limit. Tokens are minted by the shared
 * {@link DelegatedTokenMinter} — a service-account key, workload identity
 * federation, or Application Default Credentials, depending on deployment. */
@Component
// Shared with the Directory client and the token minter so all three activate
// together; see GoogleCredentialsConfiguration.CONFIGURED. Falls back to
// UnavailableDriveAttachmentStore when it does not hold.
@ConditionalOnExpression(ua.kse.passwordmanager.google.GoogleCredentialsConfiguration.CONFIGURED)
public class GoogleDriveAttachmentStore implements DriveAttachmentStore {
    private static final List<String> SCOPES = List.of("https://www.googleapis.com/auth/drive.appdata");
    /** Must be a multiple of 256 KiB for every non-final resumable chunk. */
    private static final int CHUNK_SIZE = 8 * 1024 * 1024;
    private final RestClient drive = RestClient.create("https://www.googleapis.com/drive/v3/");
    private final RestClient upload = RestClient.create("https://www.googleapis.com/upload/drive/v3/");
    private final RestClient sessionUpload = RestClient.create();
    private final ObjectMapper json;
    private final DelegatedTokenMinter minter;

    public GoogleDriveAttachmentStore(ObjectMapper json, DelegatedTokenMinter minter) {
        this.json = json;
        this.minter = minter;
    }

    @Override public String upload(String ownerEmail, InputStream ciphertext, long expectedSize, String ciphertextSha256) {
        try {
            String token = token(ownerEmail);
            String metadata = json.writeValueAsString(Map.of("name", "pm-" + java.util.UUID.randomUUID(),
                    "parents", List.of("appDataFolder"), "mimeType", MediaType.APPLICATION_OCTET_STREAM_VALUE));
            var initiated = upload.post().uri("files?uploadType=resumable&fields=id")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header("X-Upload-Content-Type", MediaType.APPLICATION_OCTET_STREAM_VALUE)
                    .header("X-Upload-Content-Length", Long.toString(expectedSize))
                    .contentType(MediaType.APPLICATION_JSON).body(metadata).retrieve().toBodilessEntity();
            String session = initiated.getHeaders().getFirst(HttpHeaders.LOCATION);
            if (session == null || session.isBlank()) throw new BadGatewayException("Google Drive did not start a resumable upload", null);

            MessageDigest digest = sha256Digest();
            String fileId;
            if (expectedSize == 0) {
                String result = sessionUpload.put().uri(session)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .header(HttpHeaders.CONTENT_RANGE, "bytes */0")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).body(new byte[0]).retrieve().body(String.class);
                fileId = extractId(result);
            } else {
                fileId = uploadChunks(session, token, ciphertext, expectedSize, digest);
            }
            if (fileId == null || fileId.isBlank()) throw new BadGatewayException("Google Drive upload did not return a file ID", null);

            String actualSha256 = HexFormat.of().formatHex(digest.digest());
            if (!actualSha256.equalsIgnoreCase(ciphertextSha256)) {
                delete(ownerEmail, fileId);
                throw new IllegalArgumentException("Attachment ciphertext size or SHA-256 does not match its metadata");
            }
            return fileId;
        } catch (RestClientResponseException e) { throw mapped(e); }
        catch (BadGatewayException | IllegalArgumentException e) { throw e; }
        catch (IOException e) { throw new BadGatewayException("Failed to read attachment ciphertext", e); }
        catch (Exception e) { throw new BadGatewayException("Google Drive upload failed", e); }
    }

    /** Uploads the stream to an already-initiated resumable session in fixed
     * chunks, hashing as it goes so the caller never needs the whole file in
     * memory to verify it. Returns the file id from the final chunk's response. */
    private String uploadChunks(String session, String token, InputStream ciphertext, long expectedSize, MessageDigest digest) throws IOException {
        byte[] buffer = new byte[CHUNK_SIZE];
        long sent = 0;
        while (sent < expectedSize) {
            int read = readFully(ciphertext, buffer);
            if (read <= 0) throw new IllegalArgumentException("Attachment ciphertext ended before its declared size");
            digest.update(buffer, 0, read);
            boolean last = sent + read >= expectedSize;
            byte[] chunk = read == buffer.length ? buffer : Arrays.copyOf(buffer, read);
            String range = "bytes " + sent + "-" + (sent + read - 1) + "/" + expectedSize;
            ResponseEntity<String> response = sessionUpload.put().uri(session)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(HttpHeaders.CONTENT_RANGE, range)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM).body(chunk)
                    .retrieve().toEntity(String.class);
            sent += read;
            if (last) return extractId(response.getBody());
            if (response.getStatusCode().value() != 308) {
                throw new BadGatewayException("Google Drive rejected an intermediate upload chunk (HTTP " + response.getStatusCode().value() + ")", null);
            }
        }
        throw new IllegalArgumentException("Attachment ciphertext ended before its declared size");
    }

    private static int readFully(InputStream in, byte[] buffer) throws IOException {
        int total = 0;
        while (total < buffer.length) {
            int n = in.read(buffer, total, buffer.length - total);
            if (n < 0) break;
            total += n;
        }
        return total;
    }

    private String extractId(String responseBody) throws IOException {
        if (responseBody == null || responseBody.isBlank()) return null;
        return json.readTree(responseBody).path("id").asText();
    }

    @Override public void download(String ownerEmail, String driveFileId, OutputStream out) {
        try {
            drive.get().uri("files/{id}?alt=media", driveFileId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ownerEmail))
                    .exchange((clientRequest, clientResponse) -> {
                        HttpStatusCode status = clientResponse.getStatusCode();
                        if (status.isError()) {
                            byte[] body = clientResponse.getBody().readAllBytes();
                            throw new RestClientResponseException("Google Drive download failed", status.value(),
                                    "", clientResponse.getHeaders(), body, StandardCharsets.UTF_8);
                        }
                        clientResponse.getBody().transferTo(out);
                        return null;
                    });
        } catch (RestClientResponseException e) { throw mapped(e); }
        catch (Exception e) { throw new BadGatewayException("Google Drive download failed", e); }
    }

    @Override public void delete(String ownerEmail, String driveFileId) {
        try { drive.delete().uri("files/{id}", driveFileId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ownerEmail)).retrieve().toBodilessEntity(); }
        catch (RestClientResponseException e) {
            if (e.getStatusCode().value() != 404) throw mapped(e);
        } catch (Exception e) { throw new BadGatewayException("Google Drive deletion failed", e); }
    }

    private String token(String ownerEmail) {
        AccessToken token = minter.mint(ownerEmail, SCOPES);
        return token.getTokenValue();
    }
    private static MessageDigest sha256Digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }
    private static RuntimeException mapped(RestClientResponseException e) {
        String body = e.getResponseBodyAsString(StandardCharsets.UTF_8).toLowerCase();
        if (body.contains("storagequotaexceeded") || body.contains("quotaexceeded")) {
            return new QuotaExceededException("Google Drive storage quota is exhausted for this Workspace user or organization", e);
        }
        return new BadGatewayException("Google Drive API rejected the attachment (HTTP " + e.getStatusCode().value() + ")", e);
    }
}
