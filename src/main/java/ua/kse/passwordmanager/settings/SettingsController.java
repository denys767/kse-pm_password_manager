package ua.kse.passwordmanager.settings;

import jakarta.validation.Valid;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;

@RestController
@RequestMapping("/api/settings")
public class SettingsController {

    private final UserSettingsRepository repository;
    private final AuthFacade authFacade;

    public SettingsController(UserSettingsRepository repository, AuthFacade authFacade) {
        this.repository = repository;
        this.authFacade = authFacade;
    }

    @GetMapping
    public SettingsDto get() {
        String email = authFacade.current().email();
        return SettingsDto.from(repository.findById(email).orElseGet(() -> new UserSettings(email)));
    }

    @PutMapping
    @Transactional
    public SettingsDto update(@Valid @RequestBody SettingsDto dto) {
        String email = authFacade.current().email();
        UserSettings settings = repository.findById(email).orElseGet(() -> new UserSettings(email));
        settings.setDefaultSyncMode(dto.defaultSyncMode());
        settings.setClipboardClearSeconds(dto.clipboardClearSeconds());
        return SettingsDto.from(repository.save(settings));
    }
}
