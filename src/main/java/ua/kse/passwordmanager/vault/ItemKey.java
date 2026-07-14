package ua.kse.passwordmanager.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
 * The item's AES key, wrapped (RSA-OAEP) with one user's public key. One row
 * per (item, user) that can decrypt the item. The server only ever stores the
 * wrapped form.
 */
@Entity
@Table(name = "item_keys",
        uniqueConstraints = @UniqueConstraint(columnNames = {"item_id", "userEmail"}))
public class ItemKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "item_id")
    private PasswordItem item;

    @Column(nullable = false)
    private String userEmail;

    @Column(nullable = false, length = 4096)
    private String wrappedKey;

    @Column(nullable = false)
    private Instant createdAt;

    protected ItemKey() {
    }

    public ItemKey(PasswordItem item, String userEmail, String wrappedKey) {
        this.item = item;
        this.userEmail = userEmail;
        this.wrappedKey = wrappedKey;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public PasswordItem getItem() {
        return item;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getWrappedKey() {
        return wrappedKey;
    }

    public void setWrappedKey(String wrappedKey) {
        this.wrappedKey = wrappedKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
