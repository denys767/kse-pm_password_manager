package ua.kse.passwordmanager.vault;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.NotFoundException;

/** Workspace-wide tag maintenance for ciphertext-free item metadata.
 * Tags are normalised case-insensitively but retain the spelling selected by
 * the admin.  Each mutation is one database transaction. */
@Service
public class AdminTagService {
    private static final int MAX_TAGS_LENGTH = 1024;
    private final PasswordItemRepository items;
    private final AuditService audit;

    public AdminTagService(PasswordItemRepository items, AuditService audit) {
        this.items = items;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<TagSummary> list() {
        Map<String, TagSummary> result = new LinkedHashMap<>();
        for (PasswordItem item : serverItems()) {
            for (String tag : parse(item.getTags())) {
                String key = key(tag);
                TagSummary existing = result.get(key);
                result.put(key, existing == null ? new TagSummary(tag, 1)
                        : new TagSummary(existing.name(), existing.usageCount() + 1));
            }
        }
        return result.values().stream().sorted(Comparator.comparing(TagSummary::name,
                String.CASE_INSENSITIVE_ORDER)).toList();
    }

    @Transactional
    public TagSummary rename(CurrentUser actor, String oldName, String newName) {
        String oldTag = requireTag(oldName, "Tag");
        String replacement = requireTag(newName, "newName");
        String oldKey = key(oldTag);
        int affected = 0;
        for (PasswordItem item : serverItems()) {
            List<String> current = parse(item.getTags());
            if (current.stream().noneMatch(tag -> key(tag).equals(oldKey))) continue;
            List<String> next = new ArrayList<>();
            for (String tag : current) next.add(key(tag).equals(oldKey) ? replacement : tag);
            item.setTags(serialise(next));
            affected++;
        }
        if (affected == 0) throw new NotFoundException("Tag not found");
        audit.record(actor.email(), AuditAction.ITEM_UPDATED, null, null, oldTag,
                "workspace tag renamed to '" + replacement + "' on " + affected + " record(s)");
        return new TagSummary(replacement, count(replacement));
    }

    @Transactional
    public void delete(CurrentUser actor, String name) {
        String tag = requireTag(name, "Tag");
        String target = key(tag);
        int affected = 0;
        for (PasswordItem item : serverItems()) {
            List<String> current = parse(item.getTags());
            List<String> next = current.stream().filter(candidate -> !key(candidate).equals(target)).toList();
            if (next.size() == current.size()) continue;
            item.setTags(serialise(next));
            affected++;
        }
        if (affected == 0) throw new NotFoundException("Tag not found");
        audit.record(actor.email(), AuditAction.ITEM_UPDATED, null, null, tag,
                "workspace tag deleted from " + affected + " record(s)");
    }

    private List<PasswordItem> serverItems() {
        return items.findBySyncMode(SyncMode.SERVER_SYNCED);
    }

    private int count(String tag) {
        String lookup = key(tag);
        return (int) serverItems().stream().filter(item -> parse(item.getTags()).stream()
                .anyMatch(candidate -> key(candidate).equals(lookup))).count();
    }

    static List<String> parse(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        Map<String, String> unique = new LinkedHashMap<>();
        for (String candidate : raw.split(",")) {
            String tag = candidate.trim();
            if (!tag.isEmpty()) unique.putIfAbsent(key(tag), tag);
        }
        return List.copyOf(unique.values());
    }

    private static String serialise(List<String> tags) {
        List<String> normalised = parse(String.join(",", tags));
        String value = normalised.isEmpty() ? null : String.join(",", normalised);
        if (value != null && value.length() > MAX_TAGS_LENGTH) {
            throw new BadRequestException("Tag operation would exceed the 1024 character tag limit");
        }
        return value;
    }

    private static String requireTag(String value, String field) {
        if (value == null || value.trim().isEmpty()) throw new BadRequestException(field + " must not be blank");
        String result = value.trim();
        if (result.contains(",")) throw new BadRequestException(field + " must contain one tag, not a comma-separated list");
        if (result.length() > MAX_TAGS_LENGTH) throw new BadRequestException(field + " is too long");
        return result;
    }

    private static String key(String tag) {
        return tag.trim().toLowerCase(Locale.ROOT);
    }

    public record TagSummary(String name, int usageCount) { }
}
