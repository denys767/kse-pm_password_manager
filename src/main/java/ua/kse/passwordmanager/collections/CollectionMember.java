package ua.kse.passwordmanager.collections;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * Membership row: who is in the collection, with what role, and the
 * collection key wrapped (RSA-OAEP) with this member's public key. Only a
 * member holding the unwrapped collection key can add new members, because
 * provisioning requires re-wrapping that key for the newcomer.
 */
@Entity
@Table(name = "collection_members",
        uniqueConstraints = @UniqueConstraint(columnNames = {"collection_id", "memberEmail"}))
public class CollectionMember {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "collection_id")
    private Collection collection;

    @Column(nullable = false)
    private String memberEmail;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CollectionRole role;

    @Column(nullable = false, length = 4096)
    private String wrappedKey;

    @Column(nullable = false)
    private String addedBy;

    @Column(nullable = false)
    private Instant createdAt;

    protected CollectionMember() {
    }

    public CollectionMember(Collection collection, String memberEmail, CollectionRole role,
                            String wrappedKey, String addedBy) {
        this.collection = collection;
        this.memberEmail = memberEmail;
        this.role = role;
        this.wrappedKey = wrappedKey;
        this.addedBy = addedBy;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public Collection getCollection() {
        return collection;
    }

    public String getMemberEmail() {
        return memberEmail;
    }

    public CollectionRole getRole() {
        return role;
    }

    public void setRole(CollectionRole role) {
        this.role = role;
    }

    public String getWrappedKey() {
        return wrappedKey;
    }

    public void setWrappedKey(String wrappedKey) {
        this.wrappedKey = wrappedKey;
    }

    public String getAddedBy() {
        return addedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
