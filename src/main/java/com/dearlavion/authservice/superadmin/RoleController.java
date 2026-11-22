package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.access.AccessService;
import com.dearlavion.authservice.access.PermissionDef;
import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.common.exception.ConflictException;
import com.dearlavion.authservice.common.exception.NotFoundException;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Roles for the security dashboard: "Admin", "Simple User", "Guest"... each linking permission keys. A role is either a
 * <em>default</em> (no customer in the path: every project can assign it, so nobody sets it up twice) or one project's own.
 * Users hold a role live, so editing one applies to everybody who has it. Behind {@link SuperAdminAuthFilter}.
 */
@RestController
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class RoleController {

    private static final int MAX_PAGE_SIZE = 100;

    /**
     * For a PATCH every field is optional; for a create, name and permissionKeys (may be empty) are needed. There is no account type to
     * send: it follows from the permissions (see {@link #accountTypeFor}), except on the built-in Admin and User roles, which keep theirs.
     */
    public record RoleRequest(String name, String description, List<String> permissionKeys) {}
    public record RoleView(String id, String name, String description, Role accountType, List<String> permissionKeys, boolean isDefault,
                           boolean builtIn, long userCount, String createdBy, Instant createdAt) {}
    /** {@code customer} is null for a default role. */
    public record ScopedRole(String customer, RoleView role) {}
    public record ScopedRolePage(List<ScopedRole> items, long total, int page, int size) {}

    private final ScopeResolver scopes;
    private final TenantService tenants;
    private final UserService userService;
    private final AuditLog audit;

    @PostMapping({"/projects/{customer}/roles", "/defaults/roles"})
    public RoleView create(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable(required = false) String customer, @RequestBody RoleRequest body) {
        String scope = scopes.scope(customer);
        if (body == null) throw new BadRequestException("Nothing to create");
        String name = cleanName(body.name());
        String description = cleanDescription(body.description());
        List<String> keys = cleanKeys(body.permissionKeys());
        Role type = accountTypeFor(keys);
        checkKeys(scope, keys);
        if (nameTaken(scope, name, null)) throw new ConflictException(nameClash(scope, name));
        try {
            PermissionRole saved = scopes.db(scope).insert(new PermissionRole(null, name, description, type, keys, false, actor.username(), Instant.now()));
            audit.record(actor.username(), "ROLE_CREATE", scopes.label(scope), name, null, summary(saved));
            return view(scope, saved);
        } catch (DuplicateKeyException e) {
            throw new ConflictException(nameClash(scope, name));
        }
    }

    /** Roles across scopes, ordered by scope (defaults first) then name. {@code customer=*} is only the defaults; a project shows the defaults plus its own. */
    @GetMapping("/roles")
    public ScopedRolePage list(@RequestParam(required = false) String customer,
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
            counts[i] = scopes.db(scopeNames.get(i)).count(Query.query(match), PermissionRole.class);
            total += counts[i];
        }
        List<ScopedRole> items = new ArrayList<>();
        for (ProjectPaging.Segment s : ProjectPaging.plan(scopeNames, counts, pageIndex, pageSize)) {
            Query query = Query.query(match).with(Sort.by("name")).skip(s.skip()).limit(s.take());
            scopes.db(s.project()).find(query, PermissionRole.class)
                    .forEach(r -> items.add(new ScopedRole(scopes.customerOf(s.project()), view(s.project(), r))));
        }
        return new ScopedRolePage(items, total, pageIndex, pageSize);
    }

    @PatchMapping({"/projects/{customer}/roles/{id}", "/defaults/roles/{id}"})
    public RoleView update(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable(required = false) String customer, @PathVariable String id, @RequestBody RoleRequest body) {
        String scope = scopes.scope(customer);
        MongoTemplate db = scopes.db(scope);
        PermissionRole role = db.findById(id, PermissionRole.class);
        if (role == null) throw new NotFoundException("Role not found");
        if (body == null) throw new BadRequestException("Nothing to update");
        String before = summary(role);
        Role previousType = role.getAccountType();

        // Admin and User keep their identity; what they grant, and their description, are the superadmin's to set.
        if (role.isBuiltIn() && body.name() != null && !body.name().trim().equalsIgnoreCase(role.getName())) {
            throw new BadRequestException("A built-in role can't be renamed");
        }
        if (body.name() != null && !role.isBuiltIn()) {
            String name = cleanName(body.name());
            if (nameTaken(scope, name, id)) throw new ConflictException(nameClash(scope, name));
            role.setName(name);
        }
        if (body.description() != null) role.setDescription(cleanDescription(body.description()));
        if (body.permissionKeys() != null) {
            List<String> keys = cleanKeys(body.permissionKeys());
            checkKeys(scope, keys);
            role.setPermissionKeys(keys);
            // A role's account type follows what it grants, so editing the permissions can move its holders between admin and user.
            if (!role.isBuiltIn()) role.setAccountType(accountTypeFor(keys));
        }
        try {
            db.save(role);
        } catch (DuplicateKeyException e) {
            throw new ConflictException(nameClash(scope, role.getName()));
        }
        if (role.getAccountType() != previousType) {
            // Holders follow the role's account type, wherever they are: every project for a default role.
            for (String holderScope : ScopeResolver.DEFAULTS.equals(scope) ? tenants.projects() : List.of(scope)) {
                userService.syncAccountType(holderScope, id, role.getAccountType());
            }
        }
        audit.record(actor.username(), "ROLE_UPDATE", scopes.label(scope), role.getName(), before, summary(role));
        return view(scope, role);
    }

    @DeleteMapping({"/projects/{customer}/roles/{id}", "/defaults/roles/{id}"})
    public Map<String, String> delete(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                                      @PathVariable(required = false) String customer, @PathVariable String id) {
        String scope = scopes.scope(customer);
        MongoTemplate db = scopes.db(scope);
        PermissionRole role = db.findById(id, PermissionRole.class);
        if (role == null) throw new NotFoundException("Role not found");
        if (role.isBuiltIn()) throw new BadRequestException("Built-in roles can't be deleted");
        long holders = holders(scope, id);
        if (holders > 0) throw new ConflictException(holders + (holders == 1 ? " user holds" : " users hold") + " this role; give them another role first");
        db.remove(role);
        audit.record(actor.username(), "ROLE_DELETE", scopes.label(scope), role.getName(), summary(role), null);
        return Map.of("message", "Role deleted");
    }

    /** Users holding the role: across every project for a default role, in the one project for a project's own. */
    private long holders(String scope, String roleId) {
        long total = 0;
        for (String project : ScopeResolver.DEFAULTS.equals(scope) ? tenants.projects() : List.of(scope)) {
            total += userService.countWithRole(project, roleId);
        }
        return total;
    }

    /** The permission keys must exist: default roles may only use default permissions, a project's role those plus the project's own. */
    private void checkKeys(String scope, List<String> keys) {
        if (keys.isEmpty()) return;
        Query query = Query.query(Criteria.where("key").in(keys));
        Set<String> known = new LinkedHashSet<>();
        for (String s : ScopeResolver.DEFAULTS.equals(scope) ? List.of(scope) : List.of(ScopeResolver.DEFAULTS, scope)) {
            scopes.db(s).find(query, PermissionDef.class).forEach(p -> known.add(p.getKey()));
        }
        List<String> missing = keys.stream().filter(k -> !known.contains(k)).toList();
        if (!missing.isEmpty()) {
            throw new BadRequestException("Unknown permission: " + String.join(", ", missing)
                    + (ScopeResolver.DEFAULTS.equals(scope) ? " (a default role can only use default permissions)" : ""));
        }
    }

    /** Role names are unique across the scopes they can meet in: a default name can't be reused by any project, and vice versa. */
    private boolean nameTaken(String scope, String name, String excludeId) {
        Query query = Query.query(Criteria.where("name").regex("^" + Pattern.quote(name) + "$", "i"));
        for (String peer : scopes.peers(scope)) {
            PermissionRole found = scopes.db(peer).findOne(query, PermissionRole.class);
            if (found != null && !found.getId().equals(excludeId)) return true;
        }
        return false;
    }

    private String nameClash(String scope, String name) {
        return "A role named \"" + name + "\" already exists" + (ScopeResolver.DEFAULTS.equals(scope) ? " in a project or the defaults" : " here or in the defaults");
    }

    private RoleView view(String scope, PermissionRole r) {
        return new RoleView(r.getId(), r.getName(), r.getDescription(), r.getAccountType(),
                r.getPermissionKeys() == null ? List.of() : r.getPermissionKeys(), ScopeResolver.DEFAULTS.equals(scope),
                r.isBuiltIn(), holders(scope, r.getId()), r.getCreatedBy(), r.getCreatedAt());
    }

    private static String summary(PermissionRole r) {
        return r.getAccountType() + " [" + String.join(", ", r.getPermissionKeys() == null ? List.of() : r.getPermissionKeys()) + "]";
    }

    private static String cleanName(String name) {
        String trimmed = name == null ? "" : name.trim();
        if (trimmed.length() < 2 || trimmed.length() > 60) throw new BadRequestException("Name must be 2-60 characters");
        return trimmed;
    }

    private static String cleanDescription(String description) {
        if (description == null || description.isBlank()) return null;
        if (description.trim().length() > 200) throw new BadRequestException("Description is too long (200 characters at most)");
        return description.trim();
    }

    /** The permissions that open a project's admin area. A role linking any of them gives its holders the legacy ADMIN account type, else USER. */
    private static final Set<String> ADMIN_AREA = Set.of(AccessService.READ, AccessService.CREATE, AccessService.UPDATE, AccessService.DELETE);

    private static Role accountTypeFor(List<String> keys) {
        return keys.stream().anyMatch(ADMIN_AREA::contains) ? Role.ADMIN : Role.USER;
    }

    private static List<String> cleanKeys(List<String> keys) {
        if (keys == null) throw new BadRequestException("permissionKeys is required (it can be empty)");
        return keys.stream().filter(k -> k != null && !k.isBlank()).map(k -> k.trim().toLowerCase()).distinct().toList();
    }

    private static Criteria matching(String q) {
        if (q == null || q.isBlank()) return new Criteria();
        String pattern = ".*" + Pattern.quote(q.trim()) + ".*";
        return new Criteria().orOperator(Criteria.where("name").regex(pattern, "i"), Criteria.where("description").regex(pattern, "i"));
    }
}
