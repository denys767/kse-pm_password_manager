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
     * Google Workspace is the source of truth for profile photos: whoever has one
     * there sees it everywhere in the app, and the manually uploaded avatar only
     * covers accounts without a Google photo.
     */
    private String resolveAvatar(String email, String manualAvatarDataUrl) {
        String fromGoogle = directoryUsers.findById(email).map(WorkspaceUser::getAvatarDataUrl).orElse(null);
        return fromGoogle != null && !fromGoogle.isBlank() ? fromGoogle : manualAvatarDataUrl;
    }

    @GetMapping
    public SettingsDto get() {
        String email = authFacade.current().email();
        UserSettings settings = repository.findById(email).orElseGet(() -> new UserSettings(email));
        return SettingsDto.from(settings, resolveAvatar(email, settings.getAvatarDataUrl()));
    }

    @PutMapping
    @Transactional
    public SettingsDto update(@Valid @RequestBody SettingsDto dto) {
        String email = authFacade.current().email();
        UserSettings settings = repository.findById(email).orElseGet(() -> new UserSettings(email));
        settings.setDefaultSyncMode(dto.defaultSyncMode());
        settings.setClipboardClearSeconds(dto.clipboardClearSeconds());
        settings.setAvatarDataUrl(dto.avatarDataUrl());
        UserSettings saved = repository.save(settings);
        return SettingsDto.from(saved, resolveAvatar(email, saved.getAvatarDataUrl()));
    }

    /** Any authenticated user can look up another user's avatar — same visibility as their public key. */
    @GetMapping("/{email}/avatar")
    public AvatarDto avatar(@PathVariable String email) {
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        String manual = repository.findById(normalized).map(UserSettings::getAvatarDataUrl).orElse(null);
        return new AvatarDto(resolveAvatar(normalized, manual));
    }

    public record AvatarDto(String avatarDataUrl) { }
}
