package ua.kse.passwordmanager.collections;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.collections.CollectionDtos.AddMemberRequest;
import ua.kse.passwordmanager.collections.CollectionDtos.CollectionResponse;
import ua.kse.passwordmanager.collections.CollectionDtos.CreateCollectionRequest;
import ua.kse.passwordmanager.collections.CollectionDtos.MemberResponse;
import ua.kse.passwordmanager.collections.CollectionDtos.UpdateMemberRequest;

@RestController
@RequestMapping("/api/collections")
public class CollectionsController {

    private final CollectionService collectionService;
    private final AuthFacade authFacade;

    public CollectionsController(CollectionService collectionService, AuthFacade authFacade) {
        this.collectionService = collectionService;
        this.authFacade = authFacade;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CollectionResponse create(@Valid @RequestBody CreateCollectionRequest request) {
        return collectionService.create(authFacade.current(), request);
    }

    @GetMapping
    public List<CollectionResponse> list() {
        return collectionService.listMine(authFacade.current());
    }

    @GetMapping("/{id}/members")
    public List<MemberResponse> members(@PathVariable UUID id) {
        return collectionService.members(authFacade.current(), id);
    }

    @PostMapping("/{id}/members")
    @ResponseStatus(HttpStatus.CREATED)
    public MemberResponse addMember(@PathVariable UUID id,
                                    @Valid @RequestBody AddMemberRequest request) {
        return collectionService.addMember(authFacade.current(), id, request);
    }

    @PutMapping("/{id}/members/{memberId}")
    public MemberResponse changeRole(@PathVariable UUID id, @PathVariable UUID memberId,
                                     @Valid @RequestBody UpdateMemberRequest request) {
        return collectionService.changeRole(authFacade.current(), id, memberId, request.role());
    }

    @DeleteMapping("/{id}/members/{memberId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removeMember(@PathVariable UUID id, @PathVariable UUID memberId) {
        collectionService.removeMember(authFacade.current(), id, memberId);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        collectionService.delete(authFacade.current(), id);
    }
}
