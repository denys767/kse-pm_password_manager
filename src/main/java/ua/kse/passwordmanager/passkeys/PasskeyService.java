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
    public PasskeyService(PasskeyCredentialRepository credentials, PasskeyCredentialKeyRepository keys,
                          PasswordItemRepository items, SharingService sharing, AuditService audit) {
        this.credentials = credentials; this.keys = keys; this.items = items; this.sharing = sharing; this.audit = audit;
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
