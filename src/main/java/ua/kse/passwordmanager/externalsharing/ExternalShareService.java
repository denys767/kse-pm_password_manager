package ua.kse.passwordmanager.externalsharing;

import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.GoneException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;

@Service
public class ExternalShareService {
    private final ExternalShareRepository shares;
    private final PasswordItemRepository items;
    private final AuditService audit;

    public ExternalShareService(ExternalShareRepository shares, PasswordItemRepository items,
                                AuditService audit) {
        this.shares = shares;
        this.items = items;
        this.audit = audit;
    }

    @Transactional
    public ExternalShareDtos.CreatedResponse create(CurrentUser user, UUID itemId,
                                                    ExternalShareDtos.CreateRequest request) {
        PasswordItem item = ownedItem(user, itemId);
        ExternalShare share = shares.save(new ExternalShare(item, user.email(), request.encryptedPackage(),
                request.packageIv(), request.expiresAt(), request.oneTime()));
        audit.record(user.email(), AuditAction.EXTERNAL_SHARE_CREATED, itemId, item.getName(),
                share.getId().toString(), "expiresAt=" + request.expiresAt() + ", oneTime=" + request.oneTime());
        return new ExternalShareDtos.CreatedResponse(share.getId(), share.getExpiresAt(), share.isOneTime());
    }

    /** Serialized with a pessimistic row lock so a one-time package has one reader. */
    // Commit the one-off expiry audit marker before translating the read into
    // HTTP 410; otherwise the exception would roll the marker back.
    @Transactional(noRollbackFor = GoneException.class)
    public ExternalShareDtos.PublicPackageResponse read(UUID id) {
        ExternalShare share = shares.findForPublicRead(id)
                .orElseThrow(() -> new GoneException("External share is no longer available"));
        if (!share.getExpiresAt().isAfter(Instant.now())) {
            if (!share.isExpiredAudited()) {
                audit.record(share.getOwnerEmail(), AuditAction.EXTERNAL_SHARE_EXPIRED,
                        share.getItem().getId(), share.getItem().getName(), share.getId().toString(), null);
                share.setExpiredAudited(true);
            }
            throw new GoneException("External share has expired");
        }
        ExternalShareDtos.PublicPackageResponse response = new ExternalShareDtos.PublicPackageResponse(
                share.getEncryptedPackage(), share.getPackageIv(), share.getExpiresAt(), share.isOneTime());
        audit.record(share.getOwnerEmail(), AuditAction.EXTERNAL_SHARE_VIEWED,
                share.getItem().getId(), share.getItem().getName(), share.getId().toString(),
                "oneTime=" + share.isOneTime());
        if (share.isOneTime()) {
            shares.delete(share);
        }
        return response;
    }

    @Transactional
    public void revoke(CurrentUser user, UUID itemId, UUID shareId) {
        ownedItem(user, itemId);
        ExternalShare share = shares.findByIdAndOwnerEmail(shareId, user.email())
                .filter(candidate -> candidate.getItem().getId().equals(itemId))
                .orElseThrow(() -> new NotFoundException("External share not found"));
        shares.delete(share);
        audit.record(user.email(), AuditAction.EXTERNAL_SHARE_REVOKED, itemId, share.getItem().getName(),
                shareId.toString(), null);
    }

    private PasswordItem ownedItem(CurrentUser user, UUID itemId) {
        PasswordItem item = items.findById(itemId)
                .orElseThrow(() -> new NotFoundException("Item not found"));
        if (!item.getOwnerEmail().equalsIgnoreCase(user.email())) {
            throw new ForbiddenException("Only the owner can manage external shares");
        }
        return item;
    }
}
