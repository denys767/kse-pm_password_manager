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
            @Size(max = 255) String directoryGroup,
            /** Collection key wrapped with the creator's own public key. */
            @NotBlank @Size(max = 4096) String wrappedKeyForSelf) {
    }

    public record CollectionResponse(
            UUID id,
            String name,
            String ownerEmail,
            String directoryGroup,
            CollectionRole myRole,
            /** Collection key wrapped for the requesting member. */
            String myWrappedKey,
            int memberCount,
            int pendingProvisioningCount,
            int pendingRemovalCount,
            Instant createdAt) {

        static CollectionResponse from(Collection collection, CollectionMember me, int memberCount,
                                       int pendingProvisioningCount, int pendingRemovalCount) {
            return new CollectionResponse(collection.getId(), collection.getName(),
                    collection.getOwnerEmail(), collection.getDirectoryGroup(), me.getRole(), me.getWrappedKey(), memberCount,
                    pendingProvisioningCount, pendingRemovalCount,
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
            CollectionMemberStatus status,
            String addedBy,
            Instant createdAt) {

        static MemberResponse from(CollectionMember member) {
            return new MemberResponse(member.getId(), member.getMemberEmail(), member.getRole(), member.getStatus(),
                    member.getAddedBy(), member.getCreatedAt());
        }
    }
}
