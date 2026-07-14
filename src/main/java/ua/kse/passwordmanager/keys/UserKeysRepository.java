package ua.kse.passwordmanager.keys;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserKeysRepository extends JpaRepository<UserKeys, String> {
}
