package ua.kse.passwordmanager.collections;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

public final class CollectionDtos {

    private CollectionDtos() {
    }

    public record CreateCollectionRequest(
            @NotBlank @Size(max = 255) String name,
            @Size(max = 255) String keycloakGroup,
            /** Collection key wrapped with the creator's own public key. */
            @NotBlank @Size(max = 4096) String wrappedKeyForSelf) {
    }

    public record CollectionResponse(
            UUID id,
            String name,
            String ownerEmail,
            String keycloakGroup,
            CollectionRole myRole,
            /** Collection key wrapped for the requesting member. */
            String myWrappedKey,
            int memberCount,
            Instant createdAt) {

        static CollectionResponse from(Collection collection, CollectionMember me, int memberCount) {
            return new CollectionResponse(collection.getId(), collection.getName(),
                    collection.getOwnerEmail(), collection.getKeycloakGroup(), me.getRole(), me.getWrappedKey(), memberCount,
                    collection.getCreatedAt());
        }
    }

    public record AddMemberRequest(
            @NotBlank @Size(max = 255) String email,
            @NotNull CollectionRole role,
            /** Collection key wrapped with the new member's public key. */
            @NotBlank @Size(max = 4096) String wrappedKey) {
    }

    public record UpdateMemberRequest(@NotNull CollectionRole role) {
    }

    public record MemberResponse(
            UUID id,
            String memberEmail,
            CollectionRole role,
            String addedBy,
            Instant createdAt) {

        static MemberResponse from(CollectionMember member) {
            return new MemberResponse(member.getId(), member.getMemberEmail(), member.getRole(),
                    member.getAddedBy(), member.getCreatedAt());
        }
    }
}
