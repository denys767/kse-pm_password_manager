package ua.kse.passwordmanager.settings;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSettingsRepository extends JpaRepository<UserSettings, String> {
}
