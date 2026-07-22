package ua.kse.passwordmanager.sharing;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionMemberRepository extends JpaRepository<PermissionMember, UUID> {
    List<PermissionMember> findByPermissionId(UUID permissionId);
    List<PermissionMember> findByMemberEmailAndStatus(String email, PermissionMemberStatus status);
    boolean existsByPermissionItemIdAndMemberEmailAndStatus(UUID itemId, String email, PermissionMemberStatus status);
    void deleteByPermissionId(UUID permissionId);
}
