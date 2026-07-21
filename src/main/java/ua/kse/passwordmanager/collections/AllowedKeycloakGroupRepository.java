package ua.kse.passwordmanager.collections;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AllowedKeycloakGroupRepository extends JpaRepository<AllowedKeycloakGroup, String> {
    List<AllowedKeycloakGroup> findAllByOrderByGroupNameAsc();
}
