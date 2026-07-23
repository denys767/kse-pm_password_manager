package ua.kse.passwordmanager.sharing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.collections.CollectionMemberRepository;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.directory.DirectoryPrincipal;
import ua.kse.passwordmanager.directory.WorkspaceDirectoryClient;
import ua.kse.passwordmanager.directory.WorkspaceGroupRepository;
import ua.kse.passwordmanager.vault.ItemKeyRepository;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;
import ua.kse.passwordmanager.vault.SecretType;
import ua.kse.passwordmanager.vault.SyncMode;

/**
 * A production (non-dev) USER share must be accepted when the caller only knows
 * the recipient's email: the Directory API resolves a principal from its primary
 * email, so requiring the immutable id up front left users with no way to share
 * whenever the autocomplete could not suggest anyone.
 */
class SharingDirectoryResolutionTest {

    private static final String OWNER = "alice@kse.org.ua";
    private static final String RECIPIENT = "bob@kse.org.ua";

    private final PermissionRepository permissions = mock(PermissionRepository.class);
    private final PasswordItemRepository items = mock(PasswordItemRepository.class);
    private final ItemKeyRepository itemKeys = mock(ItemKeyRepository.class);
    private final CollectionMemberRepository collectionMembers = mock(CollectionMemberRepository.class);
    private final PermissionMemberRepository permissionMembers = mock(PermissionMemberRepository.class);
    private final WorkspaceDirectoryClient directory = mock(WorkspaceDirectoryClient.class);
    private final WorkspaceGroupRepository groups = mock(WorkspaceGroupRepository.class);
    private final AuditService audit = mock(AuditService.class);

    private final SharingService sharing = new SharingService(permissions, items, itemKeys, collectionMembers,
            permissionMembers, directory, groups, audit, new MockEnvironment());

    private final UUID itemId = UUID.randomUUID();
    private final PasswordItem item = new PasswordItem();

    @BeforeEach
    void itemIsOwnedByAlice() {
        item.setName("Infra");
        item.setOwnerEmail(OWNER);
        item.setType(SecretType.LOGIN);
        item.setSyncMode(SyncMode.SERVER_SYNCED);
        item.setEncryptedPassword("Y2lwaGVy");
        item.setPasswordIv("aXY=");
        when(items.findById(itemId)).thenReturn(Optional.of(item));
        when(permissions.findByItemId(itemId)).thenReturn(List.of());
        when(permissions.findByItemIdAndGranteeTypeAndGrantee(any(), any(), any())).thenReturn(Optional.empty());
        when(permissions.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(permissionMembers.findByPermissionId(any())).thenReturn(List.of());
        when(itemKeys.findByItemIdAndUserEmail(any(), any())).thenReturn(Optional.empty());
    }

    private CurrentUser owner() {
        return new CurrentUser(OWNER, "Alice", Set.of("USER"), Set.of());
    }

    private ShareRequest shareWithoutSubjectId() {
        return new ShareRequest(GranteeType.USER, RECIPIENT, PermissionRole.VIEWER, "d3JhcHBlZA==", null, null);
    }

    @Test
    void userShareWithoutDirectorySubjectIdIsResolvedByEmail() {
        when(directory.find(eq(DirectoryPrincipal.Type.USER), eq(RECIPIENT))).thenReturn(Optional.of(
                new DirectoryPrincipal(DirectoryPrincipal.Type.USER, "1234567890", RECIPIENT, "Bob", true, null)));

        PermissionResponse response = sharing.share(owner(), itemId, shareWithoutSubjectId());

        assertThat(response.grantee()).isEqualTo(RECIPIENT);
        assertThat(response.directorySubjectId()).isEqualTo("1234567890");
    }

    @Test
    void userShareIsRejectedWhenTheDirectoryDoesNotKnowTheEmail() {
        when(directory.find(any(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> sharing.share(owner(), itemId, shareWithoutSubjectId()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Directory principal was not found");
    }

    @Test
    void groupShareStillRequiresTheImmutableDirectoryId() {
        ShareRequest request = new ShareRequest(GranteeType.GROUP, "dev-team@kse.org.ua",
                PermissionRole.VIEWER, null, null, null);

        assertThatThrownBy(() -> sharing.share(owner(), itemId, request))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("directorySubjectId is required");
    }
}
