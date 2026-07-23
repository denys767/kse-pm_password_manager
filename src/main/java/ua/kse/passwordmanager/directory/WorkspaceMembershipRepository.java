package ua.kse.passwordmanager.directory;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface WorkspaceMembershipRepository extends JpaRepository<WorkspaceMembership, java.util.UUID> {
    List<WorkspaceMembership> findByGroupEmail(String groupEmail);

    /**
     * Must run as an immediate bulk statement, not the default derived-delete
     * behaviour (select-then-remove-each, deferred to the next Hibernate
     * flush): WorkspaceDirectorySyncService.sync() deletes a group's old
     * memberships and re-inserts the current ones in the same transaction.
     * Hibernate's flush always executes queued INSERTs before queued DELETEs
     * regardless of call order, so a deferred delete would let the re-insert
     * of an existing (group_email, member_email) pair collide with the row
     * it was meant to replace, violating uq_workspace_group_member on every
     * re-sync of an already-seen membership.
     */
    @Modifying
    @Query("delete from WorkspaceMembership m where m.groupEmail = :groupEmail")
    void deleteByGroupEmail(@Param("groupEmail") String groupEmail);
}
