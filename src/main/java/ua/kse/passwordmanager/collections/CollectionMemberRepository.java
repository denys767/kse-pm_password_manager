package ua.kse.passwordmanager.collections;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CollectionMemberRepository extends JpaRepository<CollectionMember, UUID> {

    List<CollectionMember> findByMemberEmail(String memberEmail);

    List<CollectionMember> findByCollectionId(UUID collectionId);

    List<CollectionMember> findByCollectionIdAndStatus(UUID collectionId, CollectionMemberStatus status);

    Optional<CollectionMember> findByCollectionIdAndMemberEmail(UUID collectionId, String memberEmail);

    Optional<CollectionMember> findByIdAndCollectionId(UUID id, UUID collectionId);

    void deleteByCollectionId(UUID collectionId);

    void deleteByCollectionIdAndMemberEmail(UUID collectionId, String memberEmail);
}
