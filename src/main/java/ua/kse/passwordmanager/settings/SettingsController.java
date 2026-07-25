package ua.kse.passwordmanager.settings;

import jakarta.validation.Valid;
import java.util.Locale;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.directory.WorkspaceUser;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;

@RestController
@RequestMapping("/api/settings")
public class SettingsController {

    private final UserSettingsRepository repository;
    private final WorkspaceUserRepository directoryUsers;
    private final AuthFacade authFacade;

    public SettingsController(UserSettingsRepository repository, WorkspaceUserRepository directoryUsers,
                              AuthFacade authFacade) {
        this.repository = repository;
        this.directoryUsers = directoryUsers;
        this.authFacade = authFacade;
    }

    /**
     * Google Workspace is the only source of profile photos: they are materialized
     * by the directory sync, so an account without a Google photo simply falls back
     * to initials in the UI. Manual uploads were removed — the stale
     * {@code user_settings.avatar_data_url} column is no longer read or written.
     */
    private String googleAvatar(String email) {
        String fromGoogle = directoryUsers.findById(email).map(WorkspaceUser::getAvatarDataUrl).orElse(null);
        return fromGoogle != null && !fromGoogle.isBlank() ? fromGoogle : null;
    }

    @GetMapping
    public SettingsDto get() {
        String email = authFacade.current().email();
        UserSettings settings = repository.findById(email).orElseGet(() -> new UserSettings(email));
        return SettingsDto.from(settings, googleAvatar(email));
    }

    @PutMapping
    @Transactional
    public SettingsDto update(@Valid @RequestBody SettingsDto dto) {
        String email = authFacade.current().email();
        UserSettings settings = repository.findById(email).orElseGet(() -> new UserSettings(email));
        settings.setDefaultSyncMode(dto.defaultSyncMode());
        settings.setClipboardClearSeconds(dto.clipboardClearSeconds());
        UserSettings saved = repository.save(settings);
        return SettingsDto.from(saved, googleAvatar(email));
    }

    /** Any authenticated user can look up another user's avatar — same visibility as their public key. */
    @GetMapping("/{email}/avatar")
    public AvatarDto avatar(@PathVariable String email) {
        return new AvatarDto(googleAvatar(email.trim().toLowerCase(Locale.ROOT)));
    }

    public record AvatarDto(String avatarDataUrl) { }
}
