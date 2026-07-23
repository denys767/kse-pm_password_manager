package ua.kse.passwordmanager.collections;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CollectionGroupsController {
    private final CollectionGroupService groups;

    public CollectionGroupsController(CollectionGroupService groups) {
        this.groups = groups;
    }

    /** Google Workspace groups a manager can attach to a collection. Google owns
     * the group list, so there is nothing for an admin to allow or disallow here. */
    @GetMapping("/api/collection-groups")
    public List<String> available() { return groups.available(); }
}
