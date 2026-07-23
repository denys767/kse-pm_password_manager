package ua.kse.passwordmanager.directory;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WorkspaceMembershipRepository extends JpaRepository<WorkspaceMembership, java.util.UUID> {
    List<WorkspaceMembership> findByGroupEmail(String groupEmail);
    void deleteByGroupEmail(String groupEmail);
}
