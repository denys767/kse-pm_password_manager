package ua.kse.passwordmanager.sharing;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionMemberRepository extends JpaRepository<PermissionMember, UUID> {
    List<PermissionMember> findByPermissionId(UUID permissionId);
    List<PermissionMember> findByMemberEmailAndStatus(String email, PermissionMemberStatus status);
    /** Scope the membership check to one grant.  Scoping only by item would
     * incorrectly let membership in one group inherit a second group grant on
     * the same record. */
    boolean existsByPermissionIdAndMemberEmailAndStatus(UUID permissionId, String email, PermissionMemberStatus status);
    void deleteByPermissionId(UUID permissionId);
    void deleteByMemberEmail(String memberEmail);
}
