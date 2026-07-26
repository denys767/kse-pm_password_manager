package ua.kse.passwordmanager.passkeys;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.sharing.AccessRole;
import ua.kse.passwordmanager.sharing.SharingService;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;

@Service
public class PasskeyService {
    private final PasskeyCredentialRepository credentials; private final PasskeyCredentialKeyRepository keys;
    private final PasswordItemRepository items; private final SharingService sharing; private final AuditService audit;
    private final ua.kse.passwordmanager.keys.UserKeysRepository userKeys;
    public PasskeyService(PasskeyCredentialRepository credentials, PasskeyCredentialKeyRepository keys,
                          PasswordItemRepository items, SharingService sharing, AuditService audit,
                          ua.kse.passwordmanager.keys.UserKeysRepository userKeys) {
        this.credentials = credentials; this.keys = keys; this.items = items; this.sharing = sharing; this.audit = audit;
        this.userKeys = userKeys;
    }
    @Transactional
    public PasskeyDtos.Response create(CurrentUser user, PasskeyDtos.CreateRequest request) {
        PasswordItem item = ownedItem(user, request.itemId());
        PasskeyCredential credential = credentials.save(new PasskeyCredential(item.getId(), user.email(),
                request.relyingPartyId().toLowerCase(Locale.ROOT), request.credentialId(), request.userHandle(),
                request.algorithm() == null ? "ES256" : request.algorithm(), request.publicKey(),
                request.encryptedPrivateMaterial(), request.privateMaterialIv(), request.transports()));
        keys.save(new PasskeyCredentialKey(credential, user.email(), request.wrappedCredentialKey()));
        audit.record(user.email(), AuditAction.PASSKEY_CREATED, item.getId(), item.getName(), request.relyingPartyId(), null);
        return response(credential, request.wrappedCredentialKey());
    }
    @Transactional(readOnly = true)
    public List<PasskeyDtos.Response> matching(CurrentUser user, String rpId) {
        return credentials.findByRelyingPartyId(rpId.toLowerCase(Locale.ROOT)).stream()
                .filter(c -> canUse(user, c))
                .map(c -> keys.findByCredentialIdAndUserEmail(c.getId(), user.email()).map(k -> response(c, k.getWrappedKey())))
                .flatMap(java.util.Optional::stream).sorted(Comparator.comparing(PasskeyDtos.Response::credentialId)).toList();
    }
    @Transactional
    public void advanceCounter(CurrentUser user, UUID id, long signCounter) {
        PasskeyCredential credential = readable(user, id);
        if (signCounter <= credential.getSignCounter() || credentials.advanceCounter(id, signCounter) != 1) {
            throw new ForbiddenException("Passkey signature counter must increase atomically");
        }
        audit.record(user.email(), AuditAction.PASSKEY_USED, credential.getItemId(), null, credential.getRelyingPartyId(), "counter=" + signCounter);
    }
    /**
     * The work the owner's extension still has to do so that PASSKEY_ONLY (and
     * every other passkey-capable grant) actually functions.
     *
     * <p>A grant on its own gives the grantee nothing: {@code matching()} only
     * returns a credential to somebody who has a {@link PasskeyCredentialKey}
     * wrapping its AES key to their public key, and only the owner's client can
     * create one — it is the only party that can unwrap its own copy. Nothing
     * used to ask for that work, so a PASSKEY_ONLY grantee saw an empty list
     * forever and the feature looked broken rather than unfinished.
     *
     * <p>Returns the owner's own wrapped key alongside each set of pending
     * grantees, so one round trip carries everything the extension needs.
     * Grantees with no vault keys yet are skipped rather than failed: they will
     * appear on a later pass, once they have a keypair to wrap to.
     */
    @Transactional(readOnly = true)
    public List<PasskeyDtos.KeyDistribution> pendingKeyDistribution(CurrentUser user) {
        List<PasswordItem> owned = items.findByOwnerEmail(user.email());
        if (owned.isEmpty()) return List.of();
        java.util.Map<UUID, PasswordItem> itemsById = owned.stream()
                .collect(java.util.stream.Collectors.toMap(PasswordItem::getId, item -> item));
        List<PasskeyCredential> credentials = this.credentials.findByItemIdIn(itemsById.keySet());
        if (credentials.isEmpty()) return List.of();
        // One query for every wrapped key across every credential, rather than
        // one per credential per candidate grantee.
        java.util.Map<UUID, java.util.Set<String>> holders = keys
                .findByCredentialIdIn(credentials.stream().map(PasskeyCredential::getId).toList()).stream()
                .collect(java.util.stream.Collectors.groupingBy(k -> k.getCredential().getId(),
                        java.util.stream.Collectors.mapping(k -> k.getUserEmail().toLowerCase(Locale.ROOT),
                                java.util.stream.Collectors.toSet())));

        List<PasskeyDtos.KeyDistribution> work = new java.util.ArrayList<>();
        for (PasskeyCredential credential : credentials) {
            PasswordItem item = itemsById.get(credential.getItemId());
            java.util.Set<String> alreadyHold = holders.getOrDefault(credential.getId(), java.util.Set.of());
            String mine = keys.findByCredentialIdAndUserEmail(credential.getId(), user.email())
                    .map(PasskeyCredentialKey::getWrappedKey).orElse(null);
            // Without the owner's own copy there is nothing to re-wrap from.
            if (mine == null) continue;
            List<PasskeyDtos.PendingGrantee> pending = sharing.passkeyCapableGrantees(item).stream()
                    .filter(email -> !alreadyHold.contains(email))
                    .map(email -> userKeys.findById(email)
                            .map(k -> new PasskeyDtos.PendingGrantee(email, k.getPublicKey())).orElse(null))
                    .filter(java.util.Objects::nonNull)
                    .toList();
            if (pending.isEmpty()) continue;
            work.add(new PasskeyDtos.KeyDistribution(credential.getId(), item.getId(), item.getName(),
                    credential.getRelyingPartyId(), mine, pending));
        }
        return work;
    }

    @Transactional
    public void putWrappedKey(CurrentUser user, UUID id, PasskeyDtos.WrappedKeyRequest request) {
        PasskeyCredential credential = credentials.findById(id).orElseThrow(() -> new NotFoundException("Passkey not found"));
        ownedItem(user, credential.getItemId());
        String email = request.userEmail().toLowerCase(Locale.ROOT);
        keys.findByCredentialIdAndUserEmail(id, email).ifPresentOrElse(k -> k.setWrappedKey(request.wrappedCredentialKey()),
                () -> keys.save(new PasskeyCredentialKey(credential, email, request.wrappedCredentialKey())));
    }
    private boolean canUse(CurrentUser user, PasskeyCredential credential) {
        return items.findById(credential.getItemId()).map(item -> sharing.resolveAccess(item, user).mayUsePasskeys()).orElse(false);
    }
    private PasskeyCredential readable(CurrentUser user, UUID id) {
        PasskeyCredential credential = credentials.findById(id).orElseThrow(() -> new NotFoundException("Passkey not found"));
        if (!canUse(user, credential) || keys.findByCredentialIdAndUserEmail(id, user.email()).isEmpty()) throw new NotFoundException("Passkey not found");
        return credential;
    }
    private PasswordItem ownedItem(CurrentUser user, UUID id) {
        PasswordItem item = items.findById(id).orElseThrow(() -> new NotFoundException("Item not found"));
        if (sharing.resolveAccess(item, user) != AccessRole.OWNER) throw new ForbiddenException("Only the owner can manage passkeys");
        return item;
    }
    private static PasskeyDtos.Response response(PasskeyCredential c, String wrappedKey) {
        return new PasskeyDtos.Response(c.getId(), c.getItemId(), c.getRelyingPartyId(), c.getCredentialId(), c.getUserHandle(),
                c.getAlgorithm(), c.getPublicKey(), c.getEncryptedPrivateMaterial(), c.getPrivateMaterialIv(), c.getTransports(), c.getSignCounter(), wrappedKey);
    }
}
