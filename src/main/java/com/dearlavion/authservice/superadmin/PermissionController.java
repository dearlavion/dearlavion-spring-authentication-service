package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.access.PermissionDef;
import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.common.exception.ConflictException;
import com.dearlavion.authservice.common.exception.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The permission catalog for the security dashboard. A permission is either a <em>default</em> (no customer in the path, applies
 * to every project) or one project's own. Behind {@link SuperAdminAuthFilter} like the rest of /superadmin.
 */
@RestController
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class PermissionController {

    private static final int MAX_PAGE_SIZE = 100;
    private static final Pattern KEY = Pattern.compile("^[a-z][a-z0-9]*([._-][a-z0-9]+)*$");

    /** {@code key} is the permission's name and unique identifier; {@code description} is optional. */
    public record PermissionRequest(String key, String description) {}
    public record PermissionView(String id, String key, String description, boolean builtIn, long roleCount,
                                 String createdBy, Instant createdAt) {}
    /** {@code customer} is null for a default permission. */
    public record ScopedPermission(String customer, PermissionView permission) {}
    public record ScopedPermissionPage(List<ScopedPermission> items, long total, int page, int size) {}

    private final ScopeResolver scopes;
    private final AuditLog audit;

    @PostMapping({"/projects/{customer}/permissions", "/defaults/permissions"})
    public PermissionView create(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                                 @PathVariable(required = false) String customer, @RequestBody PermissionRequest body) {
        String scope = scopes.scope(customer);
        if (body == null) throw new BadRequestException("Nothing to create");
        String key = cleanKey(body.key());
        String description = body.description() == null || body.description().isBlank() ? null : body.description().trim();
        if (description != null && description.length() > 200) throw new BadRequestException("Description is too long (200 characters at most)");
        checkKeyFree(scope, key, null);
        try {
            PermissionDef saved = scopes.db(scope).insert(new PermissionDef(null, key, description, false, actor.username(), Instant.now()));
            audit.record(actor.username(), "PERMISSION_CREATE", scopes.label(scope), key, null, description);
            return view(scope, saved);
        } catch (DuplicateKeyException e) {
            throw new ConflictException("A permission named \"" + key + "\" already exists");
        }
    }

    /** Permissions across scopes, ordered by scope (defaults first) then key. {@code customer=*} is only the defaults; a project shows the defaults plus its own. */
    @GetMapping("/permissions")
    public ScopedPermissionPage list(@RequestParam(required = false) String customer,
                                     @RequestParam(required = false) String q,
                                     @RequestParam(defaultValue = "0") int page,
                                     @RequestParam(defaultValue = "20") int size) {
        List<String> scopeNames = scopes.listScopes(customer);
        int pageSize = Math.max(1, Math.min(size, MAX_PAGE_SIZE));
        int pageIndex = Math.max(0, page);
        Criteria match = matching(q);

        long total = 0;
        long[] counts = new long[scopeNames.size()];
        for (int i = 0; i < counts.length; i++) {
            counts[i] = scopes.db(scopeNames.get(i)).count(Query.query(match), PermissionDef.class);
            total += counts[i];
        }
        List<ScopedPermission> items = new ArrayList<>();
        for (ProjectPaging.Segment s : ProjectPaging.plan(scopeNames, counts, pageIndex, pageSize)) {
            Query query = Query.query(match).with(Sort.by("key")).skip(s.skip()).limit(s.take());
            scopes.db(s.project()).find(query, PermissionDef.class)
                    .forEach(p -> items.add(new ScopedPermission(scopes.customerOf(s.project()), view(s.project(), p))));
        }
        return new ScopedPermissionPage(items, total, pageIndex, pageSize);
    }

    /**
     * Renames a permission and/or edits its description. Roles link permissions by name, so a rename is carried into every role that
     * links it (every project's, for a default permission); users keep their access, they just see the new name. Backends that
     * check the old name have to be updated by hand. Built-in permissions can be re-described but not renamed.
     */
    @PatchMapping({"/projects/{customer}/permissions/{id}", "/defaults/permissions/{id}"})
    public PermissionView update(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                                 @PathVariable(required = false) String customer, @PathVariable String id, @RequestBody PermissionRequest body) {
        String scope = scopes.scope(customer);
        MongoTemplate db = scopes.db(scope);
        PermissionDef permission = db.findById(id, PermissionDef.class);
        if (permission == null) throw new NotFoundException("Permission not found");
        if (body == null) throw new BadRequestException("Nothing to update");
        String before = permission.getKey() + (permission.getDescription() == null ? "" : " — " + permission.getDescription());
        String oldKey = permission.getKey();

        if (body.key() != null) {
            String newKey = cleanKey(body.key());
            if (!newKey.equals(oldKey)) {
                if (permission.isBuiltIn()) throw new BadRequestException("Built-in permissions can't be renamed");
                checkKeyFree(scope, newKey, id);
                permission.setKey(newKey);
            }
        }
        if (body.description() != null) {
            String description = body.description().trim();
            if (description.length() > 200) throw new BadRequestException("Description is too long (200 characters at most)");
            permission.setDescription(description.isEmpty() ? null : description);
        }
        try {
            db.save(permission);
        } catch (DuplicateKeyException e) {
            throw new ConflictException("A permission named \"" + permission.getKey() + "\" already exists");
        }
        if (!permission.getKey().equals(oldKey)) {
            Query linked = Query.query(Criteria.where("permissionKeys").is(oldKey));
            Update rename = new Update().set("permissionKeys.$", permission.getKey());
            for (String s : ScopeResolver.DEFAULTS.equals(scope) ? scopes.allScopes() : List.of(scope)) {
                scopes.db(s).updateMulti(linked, rename, PermissionRole.class);
            }
        }
        audit.record(actor.username(), "PERMISSION_UPDATE", scopes.label(scope), permission.getKey(), before,
                permission.getKey() + (permission.getDescription() == null ? "" : " — " + permission.getDescription()));
        return view(scope, permission);
    }

    @DeleteMapping({"/projects/{customer}/permissions/{id}", "/defaults/permissions/{id}"})
    public Map<String, String> delete(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                                      @PathVariable(required = false) String customer, @PathVariable String id) {
        String scope = scopes.scope(customer);
        MongoTemplate db = scopes.db(scope);
        PermissionDef permission = db.findById(id, PermissionDef.class);
        if (permission == null) throw new NotFoundException("Permission not found");
        if (permission.isBuiltIn()) throw new BadRequestException("Built-in permissions can't be deleted");
        long linked = roleCount(scope, permission.getKey());
        if (linked > 0) throw new ConflictException("Linked to " + linked + (linked == 1 ? " role" : " roles") + "; unlink it first");
        db.remove(permission);
        audit.record(actor.username(), "PERMISSION_DELETE", scopes.label(scope), permission.getKey(), permission.getDescription(), null);
        return Map.of("message", "Permission deleted");
    }

    /** Names are unique across the scopes they can meet in: a default name can't be used by any project, nor a project's by the defaults. */
    private void checkKeyFree(String scope, String key, String excludeId) {
        for (String peer : scopes.peers(scope)) {
            PermissionDef found = scopes.db(peer).findOne(Query.query(Criteria.where("key").is(key)), PermissionDef.class);
            if (found != null && !found.getId().equals(excludeId)) {
                throw new ConflictException("A permission named \"" + key + "\" already exists" + (peer.equals(scope) ? "" : " in " + scopes.label(peer)));
            }
        }
    }

    private static String cleanKey(String raw) {
        String key = raw == null ? "" : raw.trim().toLowerCase();
        if (key.length() < 2 || key.length() > 60 || !KEY.matcher(key).matches()) {
            throw new BadRequestException("Name must be 2-60 lower-case letters, numbers, dots, dashes or underscores, like orders.read");
        }
        return key;
    }

    /** Roles that link the key: a default permission can be linked by any role anywhere, a project's own only by its roles. */
    private long roleCount(String scope, String key) {
        Query query = Query.query(Criteria.where("permissionKeys").is(key));
        long count = 0;
        for (String s : ScopeResolver.DEFAULTS.equals(scope) ? scopes.allScopes() : List.of(scope)) {
            count += scopes.db(s).count(query, PermissionRole.class);
        }
        return count;
    }

    private PermissionView view(String scope, PermissionDef p) {
        return new PermissionView(p.getId(), p.getKey(), p.getDescription(), p.isBuiltIn(), roleCount(scope, p.getKey()),
                p.getCreatedBy(), p.getCreatedAt());
    }

    private static Criteria matching(String q) {
        if (q == null || q.isBlank()) return new Criteria();
        String pattern = ".*" + Pattern.quote(q.trim()) + ".*";
        return new Criteria().orOperator(Criteria.where("key").regex(pattern, "i"), Criteria.where("description").regex(pattern, "i"));
    }
}
