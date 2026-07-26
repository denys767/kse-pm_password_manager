package ua.kse.passwordmanager.directory;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface WorkspaceMembershipRepository extends JpaRepository<WorkspaceMembership, java.util.UUID> {
    List<WorkspaceMembership> findByGroupEmail(String groupEmail);

    /**
     * Must run as an immediate bulk statement, not the default derived-delete
     * behaviour (select-then-remove-each, deferred to the next Hibernate
     * flush): WorkspaceDirectorySnapshotWriter.sync() deletes a group's old
     * memberships and re-inserts the current ones in the same transaction.
     * Hibernate's flush always executes queued INSERTs before queued DELETEs
     * regardless of call order, so a deferred delete would let the re-insert
     * of an existing (group_email, member_email) pair collide with the row
     * it was meant to replace, violating uq_workspace_group_member on every
     * re-sync of an already-seen membership.
     *
     * <p>Carries its own {@code @Transactional} rather than relying on the
     * caller's: a bulk statement needs an active transaction, and Spring Data
     * does not supply one for {@code @Modifying @Query} methods by default. A
     * caller whose own {@code @Transactional} did not apply used to fail here
     * with TransactionRequiredException — and only here, because the
     * repository calls preceding it carry transactions of their own and
     * quietly succeed.
     */
    @Modifying
    @Transactional
    @Query("delete from WorkspaceMembership m where m.groupEmail = :groupEmail")
    void deleteByGroupEmail(@Param("groupEmail") String groupEmail);
}
