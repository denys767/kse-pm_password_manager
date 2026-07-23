package ua.kse.passwordmanager.attachment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.common.QuotaExceededException;

/** Google Drive appDataFolder transport using domain-wide delegation to the
 * record owner. Resumable upload is used for every opaque ciphertext, avoiding
 * a second application-level size policy. */
@Component
@ConditionalOnProperty(name = "pm.google-workspace.credentials-path")
public class GoogleDriveAttachmentStore implements DriveAttachmentStore {
    private static final List<String> SCOPES = List.of("https://www.googleapis.com/auth/drive.appdata");
    private final RestClient drive = RestClient.create("https://www.googleapis.com/drive/v3/");
    private final RestClient upload = RestClient.create("https://www.googleapis.com/upload/drive/v3/");
    private final ObjectMapper json;
    private final ServiceAccountCredentials service;

    public GoogleDriveAttachmentStore(ObjectMapper json,
            @Value("${pm.google-workspace.credentials-path}") String credentialsPath) {
        this.json = json;
        try (FileInputStream in = new FileInputStream(credentialsPath)) {
            service = ServiceAccountCredentials.fromStream(in);
        } catch (IOException e) { throw new IllegalStateException("Cannot load Google Drive service account", e); }
    }

    @Override public String upload(String ownerEmail, byte[] ciphertext, long expectedSize, String ciphertextSha256) {
        if (ciphertext.length != expectedSize || !sha256(ciphertext).equalsIgnoreCase(ciphertextSha256)) {
            throw new IllegalArgumentException("Attachment ciphertext size or SHA-256 does not match its metadata");
        }
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
            String range = expectedSize == 0 ? "bytes */0" : "bytes 0-" + (expectedSize - 1) + "/" + expectedSize;
            String result = RestClient.create().put().uri(session)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(HttpHeaders.CONTENT_RANGE, range)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM).body(ciphertext).retrieve().body(String.class);
            JsonNode node = json.readTree(result);
            String id = node.path("id").asText();
            if (id.isBlank()) throw new BadGatewayException("Google Drive upload did not return a file ID", null);
            return id;
        } catch (RestClientResponseException e) { throw mapped(e); }
        catch (BadGatewayException e) { throw e; }
        catch (Exception e) { throw new BadGatewayException("Google Drive upload failed", e); }
    }

    @Override public byte[] download(String ownerEmail, String driveFileId) {
        try { return drive.get().uri("files/{id}?alt=media", driveFileId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ownerEmail)).retrieve().body(byte[].class); }
        catch (RestClientResponseException e) { throw mapped(e); }
        catch (Exception e) { throw new BadGatewayException("Google Drive download failed", e); }
    }

    @Override public void delete(String ownerEmail, String driveFileId) {
        try { drive.delete().uri("files/{id}", driveFileId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ownerEmail)).retrieve().toBodilessEntity(); }
        catch (RestClientResponseException e) {
            if (e.getStatusCode().value() != 404) throw mapped(e);
        } catch (Exception e) { throw new BadGatewayException("Google Drive deletion failed", e); }
    }

    private String token(String ownerEmail) throws IOException {
        AccessToken token = service.createScoped(SCOPES).createDelegated(ownerEmail).refreshAccessToken();
        return token.getTokenValue();
    }
    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }
    private static RuntimeException mapped(RestClientResponseException e) {
        String body = e.getResponseBodyAsString(StandardCharsets.UTF_8).toLowerCase();
        if (body.contains("storagequotaexceeded") || body.contains("quotaexceeded")) {
            return new QuotaExceededException("Google Drive storage quota is exhausted for this Workspace user or organization", e);
        }
        return new BadGatewayException("Google Drive API rejected the attachment (HTTP " + e.getStatusCode().value() + ")", e);
    }
}
