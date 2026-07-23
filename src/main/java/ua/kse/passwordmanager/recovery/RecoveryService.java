package ua.kse.passwordmanager.recovery;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import javax.crypto.Cipher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import ua.kse.passwordmanager.attachment.AttachmentService;
import ua.kse.passwordmanager.audit.*;
import ua.kse.passwordmanager.collections.*;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.directory.*;
import ua.kse.passwordmanager.keys.*;
import ua.kse.passwordmanager.passkeys.*;
import ua.kse.passwordmanager.sharing.*;
import ua.kse.passwordmanager.vault.*;

/** Audited KMS escrow workflow. KMS plaintext exists only in a short-lived
 * byte array while it is immediately wrapped for a target user's public key. */
@Service
public class RecoveryService {
    private final RecoveryKeyProvider kms; private final RecoveryKeyEnvelopeRepository envelopes;
    private final RecoveryOperationRepository operations; private final UserNotificationRepository notifications;
    private final PasswordItemRepository items; private final ItemKeyRepository itemKeys;
    private final CollectionRepository collections; private final CollectionMemberRepository collectionMembers;
    private final PasskeyCredentialRepository passkeys; private final PasskeyCredentialKeyRepository passkeyKeys;
    private final UserKeysRepository userKeys; private final WorkspaceUserRepository workspaceUsers;
    private final PermissionRepository permissions; private final PermissionMemberRepository permissionMembers;
    private final AttachmentService attachments; private final AuditService audit;
    private final RecoveryMode mode;
    private final TransactionTemplate transactions;

    public RecoveryService(RecoveryKeyProvider kms, RecoveryKeyEnvelopeRepository envelopes,
            RecoveryOperationRepository operations, UserNotificationRepository notifications,
            PasswordItemRepository items, ItemKeyRepository itemKeys, CollectionRepository collections,
            CollectionMemberRepository collectionMembers, PasskeyCredentialRepository passkeys,
            PasskeyCredentialKeyRepository passkeyKeys, UserKeysRepository userKeys,
            WorkspaceUserRepository workspaceUsers, PermissionRepository permissions,
            PermissionMemberRepository permissionMembers,
            AttachmentService attachments, AuditService audit,
            @Value("${pm.recovery.mode:BACKFILL}") RecoveryMode mode,
            PlatformTransactionManager transactionManager) {
        this.kms = kms; this.envelopes = envelopes; this.operations = operations; this.notifications = notifications;
        this.items = items; this.itemKeys = itemKeys; this.collections = collections; this.collectionMembers = collectionMembers;
        this.passkeys = passkeys; this.passkeyKeys = passkeyKeys; this.userKeys = userKeys; this.workspaceUsers = workspaceUsers;
        this.permissions = permissions; this.permissionMembers = permissionMembers;
        this.attachments = attachments; this.audit = audit; this.mode = mode;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    public RecoveryDtos.PublicKeyResponse publicKey() { return new RecoveryDtos.PublicKeyResponse(kms.activeKeyVersion(), kms.publicKeyPem(), "RSA_DECRYPT_OAEP_2048_SHA256"); }

    @Transactional
    public void putEnvelope(String actor, RecoveryDtos.EnvelopeRequest request) {
        if (!kms.activeKeyVersion().equals(request.keyVersion())) throw new BadRequestException("Envelope must use the active KMS key version");
        String owner = requireResourceOwner(request.resourceType(), request.resourceId());
        if (!owner.equalsIgnoreCase(actor)) throw new ForbiddenException("Only a resource owner can upload its recovery envelope");
        envelopes.findByResourceTypeAndResourceId(request.resourceType(), request.resourceId()).ifPresentOrElse(
                envelope -> envelope.replace(request.keyVersion(), request.ciphertext()),
                () -> envelopes.save(new RecoveryKeyEnvelope(request.resourceType(), request.resourceId(), owner, request.keyVersion(), request.ciphertext())));
        audit.record(actor, AuditAction.RECOVERY_ENVELOPE_UPLOADED, request.resourceType() == RecoveryResourceType.ITEM ? request.resourceId() : null,
                null, request.resourceType() + ":" + request.resourceId(), "kmsVersion=" + request.keyVersion());
    }

    @Transactional(readOnly = true)
    public RecoveryDtos.CoverageResponse coverageFor(String owner) {
        long total = items.findByOwnerEmail(owner).size() + collections.findByOwnerEmail(owner).size();
        List<UUID> itemIds = items.findByOwnerEmail(owner).stream().map(PasswordItem::getId).toList();
        if (!itemIds.isEmpty()) total += passkeys.findByItemIdIn(itemIds).size();
        long covered = envelopes.findByOwnerEmail(owner).stream().filter(e -> resourceStillOwned(e, owner)).count();
        return new RecoveryDtos.CoverageResponse(covered, total, mode == RecoveryMode.ENFORCING);
    }

    @Transactional(readOnly = true)
    public RecoveryDtos.CoverageResponse workspaceCoverage() {
        long total = items.count() + collections.count() + passkeys.count();
        long covered = envelopes.findAll().stream().filter(e -> resourceStillOwned(e, e.getOwnerEmail())).count();
        return new RecoveryDtos.CoverageResponse(covered, total, mode == RecoveryMode.ENFORCING);
    }

    public RecoveryOperation revokeAndTransfer(String actor, String subject, RecoveryDtos.RevokeRequest request) {
        String subjectEmail = normalized(subject); String successor = normalized(request.successorEmail());
        if (subjectEmail.equals(successor)) throw new BadRequestException("Successor must be a different user");
        if (subjectEmail.equals(normalized(actor))) throw new BadRequestException("Administrators cannot revoke themselves");
        UUID operationId = transactions.execute(status -> {
            WorkspaceUser source = workspaceUsers.findById(subjectEmail).orElseThrow(() -> new NotFoundException("Workspace user not found"));
            WorkspaceUser target = workspaceUsers.findById(successor).orElseThrow(() -> new NotFoundException("Successor Workspace user not found"));
            if (source.getStatus() == WorkspaceAccountStatus.REVOKED) throw new BadRequestException("Workspace account is already revoked");
            if (!target.hasEffectiveAccess()) throw new BadRequestException("Successor must have active Workspace access");
            userKeys.findById(successor).orElseThrow(() -> new BadRequestException("Successor must create a vault keypair first"));
            RecoveryOperation op = operations.save(new RecoveryOperation(RecoveryOperationType.REVOKE_TRANSFER, actor, subjectEmail, successor, request.reason().trim()));
            source.setStatus(WorkspaceAccountStatus.SUSPENDED);
            op.running();
            audit.record(actor, AuditAction.RECOVERY_OPERATION_CREATED, null, null, subjectEmail, "operation=" + op.getId() + "; reason=" + request.reason().trim());
            return op.getId();
        });
        return runTransfer(operationId);
    }

    private RecoveryOperation runTransfer(UUID operationId) {
        try {
            transactions.executeWithoutResult(status -> {
                RecoveryOperation op = operations.findById(operationId).orElseThrow(() -> new NotFoundException("Recovery operation not found"));
                WorkspaceUser source = workspaceUsers.findById(op.getSubjectEmail()).orElseThrow(() -> new NotFoundException("Workspace user not found"));
                UserKeys successorKeys = userKeys.findById(op.getSuccessorEmail()).orElseThrow(() -> new BadRequestException("Successor must create a vault keypair first"));
                TransferPlan plan = preparePlan(op.getSubjectEmail(), successorKeys);
                applyPlan(plan, op.getSubjectEmail(), op.getSuccessorEmail());
                source.setStatus(WorkspaceAccountStatus.REVOKED);
                op.completed();
                notifications.save(new UserNotification(op.getSubjectEmail(), "RECOVERY_REVOKED", "Your workspace vault access was revoked and owned records were transferred.", op.getId()));
                notifications.save(new UserNotification(op.getSuccessorEmail(), "RECOVERY_TRANSFER", "You received ownership of recovered workspace vault records.", op.getId()));
                audit.record(op.getActorEmail(), AuditAction.RECOVERY_OPERATION_COMPLETED, null, null, op.getSubjectEmail(), "operation=" + op.getId());
                audit.record(op.getActorEmail(), AuditAction.WORKSPACE_USER_REVOKED, null, null, op.getSubjectEmail(), "successor=" + op.getSuccessorEmail());
            });
        } catch (RuntimeException failure) {
            // The transfer transaction has rolled back completely. Persist the
            // durable suspended/failed state separately so a retry cannot see a
            // partially transferred database record.
            transactions.executeWithoutResult(status -> {
                RecoveryOperation op = operations.findById(operationId).orElseThrow(() -> new NotFoundException("Recovery operation not found"));
                op.failed(safeFailure(failure));
                notifications.save(new UserNotification(op.getSubjectEmail(), "RECOVERY_PENDING", "Your workspace access is suspended while recovery transfer requires administrator attention.", op.getId()));
                audit.record(op.getActorEmail(), AuditAction.RECOVERY_OPERATION_FAILED, null, null, op.getSubjectEmail(), "operation=" + op.getId() + "; " + safeFailure(failure));
            });
        }
        return operations.findById(operationId).orElseThrow(() -> new NotFoundException("Recovery operation not found"));
    }

    public RecoveryOperation retry(String actor, UUID operationId) {
        transactions.executeWithoutResult(status -> {
            RecoveryOperation old = operations.findById(operationId).orElseThrow(() -> new NotFoundException("Recovery operation not found"));
            if (old.getOperationType() != RecoveryOperationType.REVOKE_TRANSFER || old.getStatus() == RecoveryOperationStatus.COMPLETED) throw new BadRequestException("This recovery operation cannot be retried");
            old.running();
        });
        return runTransfer(operationId);
    }

    private TransferPlan preparePlan(String subject, UserKeys successor) {
        List<PasswordItem> ownedItems = items.findByOwnerEmail(subject);
        List<ItemTransfer> itemTransfers = new ArrayList<>();
        for (PasswordItem item : ownedItems) itemTransfers.add(new ItemTransfer(item, wrapForSuccessor(requireEnvelope(RecoveryResourceType.ITEM, item.getId(), subject), successor)));
        List<Collection> ownedCollections = collections.findByOwnerEmail(subject);
        List<CollectionTransfer> collectionTransfers = new ArrayList<>();
        for (Collection collection : ownedCollections) collectionTransfers.add(new CollectionTransfer(collection, wrapForSuccessor(requireEnvelope(RecoveryResourceType.COLLECTION, collection.getId(), subject), successor)));
        List<UUID> ids = ownedItems.stream().map(PasswordItem::getId).toList();
        List<PasskeyTransfer> passkeyTransfers = new ArrayList<>();
        if (!ids.isEmpty()) for (PasskeyCredential credential : passkeys.findByItemIdIn(ids)) passkeyTransfers.add(new PasskeyTransfer(credential, wrapForSuccessor(requireEnvelope(RecoveryResourceType.PASSKEY, credential.getId(), subject), successor)));
        return new TransferPlan(itemTransfers, collectionTransfers, passkeyTransfers);
    }

    private void applyPlan(TransferPlan plan, String subject, String successor) {
        // Copy Drive blobs before changing owner_email because appDataFolder is per owner.
        for (ItemTransfer transfer : plan.items()) attachments.transferOwner(transfer.item(), subject, successor);
        for (ItemTransfer transfer : plan.items()) {
            PasswordItem item = transfer.item(); item.setOwnerEmail(successor);
            itemKeys.findByItemIdAndUserEmail(item.getId(), successor).ifPresentOrElse(k -> k.setWrappedKey(transfer.successorWrappedKey()),
                    () -> itemKeys.save(new ItemKey(item, successor, transfer.successorWrappedKey())));
            itemKeys.deleteByItemIdAndUserEmail(item.getId(), subject);
            envelopes.findByResourceTypeAndResourceId(RecoveryResourceType.ITEM, item.getId()).ifPresent(e -> e.setOwnerEmail(successor));
        }
        for (CollectionTransfer transfer : plan.collections()) {
            Collection collection = transfer.collection(); collection.setOwnerEmail(successor);
            CollectionMember member = collectionMembers.findByCollectionIdAndMemberEmail(collection.getId(), successor)
                    .orElseGet(() -> new CollectionMember(collection, successor, CollectionRole.MANAGER, transfer.successorWrappedKey(), successor));
            member.setRole(CollectionRole.MANAGER); member.setWrappedKey(transfer.successorWrappedKey()); collectionMembers.save(member);
            collectionMembers.deleteByCollectionIdAndMemberEmail(collection.getId(), subject);
            envelopes.findByResourceTypeAndResourceId(RecoveryResourceType.COLLECTION, collection.getId()).ifPresent(e -> e.setOwnerEmail(successor));
        }
        for (PasskeyTransfer transfer : plan.passkeys()) {
            PasskeyCredential credential = transfer.credential(); credential.setOwnerEmail(successor);
            passkeyKeys.findByCredentialIdAndUserEmail(credential.getId(), successor).ifPresentOrElse(k -> k.setWrappedKey(transfer.successorWrappedKey()),
                    () -> passkeyKeys.save(new PasskeyCredentialKey(credential, successor, transfer.successorWrappedKey())));
            passkeyKeys.findByCredentialIdAndUserEmail(credential.getId(), subject).ifPresent(passkeyKeys::delete);
            envelopes.findByResourceTypeAndResourceId(RecoveryResourceType.PASSKEY, credential.getId()).ifPresent(e -> e.setOwnerEmail(successor));
        }
        for (ua.kse.passwordmanager.sharing.Permission permission : permissions.findByGranteeTypeAndGrantee(GranteeType.USER, subject)) permissions.delete(permission);
        // Remove every incoming collection/group grant as well as direct
        // grants. The governed filter blocks the account immediately, while
        // deleting wrappers ensures it cannot regain material after a future
        // Directory change or an accidental status restoration.
        collectionMembers.deleteByMemberEmail(subject);
        permissionMembers.deleteByMemberEmail(subject);
        itemKeys.deleteByUserEmail(subject);
        passkeyKeys.deleteByUserEmail(subject);
    }

    private RecoveryKeyEnvelope requireEnvelope(RecoveryResourceType type, UUID id, String owner) {
        RecoveryKeyEnvelope envelope = envelopes.findByResourceTypeAndResourceId(type, id)
                .orElseThrow(() -> new BadRequestException("Recovery coverage is incomplete for " + type + " " + id));
        if (!owner.equalsIgnoreCase(envelope.getOwnerEmail())) throw new BadRequestException("Recovery envelope owner mismatch");
        return envelope;
    }
    private String wrapForSuccessor(RecoveryKeyEnvelope envelope, UserKeys successor) {
        byte[] raw = kms.decrypt(envelope.getKeyVersion(), Base64.getDecoder().decode(envelope.getCiphertext()));
        try { return Base64.getEncoder().encodeToString(LocalRecoveryKeyProvider.cipher(Cipher.ENCRYPT_MODE, publicKey(successor.getPublicKey())).doFinal(raw)); }
        catch (GeneralSecurityException e) { throw new IllegalStateException("Cannot rewrap recovered key for successor", e); }
        finally { Arrays.fill(raw, (byte) 0); }
    }
    private static PublicKey publicKey(String base64) {
        try { return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64))); }
        catch (GeneralSecurityException | IllegalArgumentException e) { throw new BadRequestException("Successor has an invalid vault public key"); }
    }
    private String requireResourceOwner(RecoveryResourceType type, UUID id) {
        return switch (type) {
            case ITEM -> items.findById(id).orElseThrow(() -> new NotFoundException("Item not found")).getOwnerEmail();
            case COLLECTION -> collections.findById(id).orElseThrow(() -> new NotFoundException("Collection not found")).getOwnerEmail();
            case PASSKEY -> passkeys.findById(id).orElseThrow(() -> new NotFoundException("Passkey not found")).getOwnerEmail();
        };
    }
    private boolean resourceStillOwned(RecoveryKeyEnvelope envelope, String owner) {
        try { return owner.equalsIgnoreCase(requireResourceOwner(envelope.getResourceType(), envelope.getResourceId())); }
        catch (RuntimeException ignored) { return false; }
    }
    private static String normalized(String email) { return email.trim().toLowerCase(Locale.ROOT); }
    private static String safeFailure(RuntimeException failure) { return failure.getMessage() == null ? "Recovery transfer failed" : failure.getMessage().substring(0, Math.min(1800, failure.getMessage().length())); }
    private record ItemTransfer(PasswordItem item, String successorWrappedKey) { }
    private record CollectionTransfer(Collection collection, String successorWrappedKey) { }
    private record PasskeyTransfer(PasskeyCredential credential, String successorWrappedKey) { }
    private record TransferPlan(List<ItemTransfer> items, List<CollectionTransfer> collections, List<PasskeyTransfer> passkeys) { }
}
