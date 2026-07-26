package ua.kse.passwordmanager.directory;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WorkspaceGroupRepository extends JpaRepository<WorkspaceGroup, String> {

    /** Mirrors the user-side query so the share picker never has to load every
     * group in the domain and filter it in memory on each keystroke. */
    Page<WorkspaceGroup> findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(
            String email, String displayName, Pageable pageable);
}
