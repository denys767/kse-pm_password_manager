package ua.kse.passwordmanager.directory;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WorkspaceUserRepository extends JpaRepository<WorkspaceUser, String> {
    Page<WorkspaceUser> findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(String email, String name, Pageable pageable);
}
