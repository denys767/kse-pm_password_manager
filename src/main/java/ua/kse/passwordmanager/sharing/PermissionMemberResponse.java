package ua.kse.passwordmanager.sharing;

import java.util.UUID;

public record PermissionMemberResponse(UUID id, String memberEmail, PermissionMemberStatus status) {
    static PermissionMemberResponse from(PermissionMember member) {
        return new PermissionMemberResponse(member.getId(), member.getMemberEmail(), member.getStatus());
    }
}
