package com.dearlavion.authservice.access;

import com.dearlavion.authservice.superadmin.PermissionRole;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.Permission;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * What a user may do. A user who holds a role gets exactly that role's permission keys, so editing the role changes them live.
 * An account without a role (everything created before roles existed) keeps its legacy access: ADMIN/STAFF get read/modify per
 * their old READ/MODIFY/BOTH/NONE value (none stored = BOTH), a plain USER gets nothing.
 */
@Service
@RequiredArgsConstructor
public class AccessService {

    public static final String READ = "read";
    public static final String CREATE = "create";
    public static final String UPDATE = "update";
    public static final String DELETE = "delete";

    private final TenantService tenants;

    /** A role by id: the project's own first, then the defaults every project shares. */
    public PermissionRole findRole(String customer, String roleId) {
        if (roleId == null || roleId.isBlank()) return null;
        PermissionRole role = tenants.db(customer).findById(roleId, PermissionRole.class);
        return role != null ? role : tenants.defaultsDb().findById(roleId, PermissionRole.class);
    }

    /** Several roles at once (for list views), keyed by id. */
    public Map<String, PermissionRole> findRoles(String customer, Collection<String> roleIds) {
        Map<String, PermissionRole> found = new HashMap<>();
        if (roleIds.isEmpty()) return found;
        Query query = Query.query(Criteria.where("id").in(roleIds));
        tenants.defaultsDb().find(query, PermissionRole.class).forEach(r -> found.put(r.getId(), r));
        tenants.db(customer).find(query, PermissionRole.class).forEach(r -> found.put(r.getId(), r));
        return found;
    }

    public Set<String> permissionsOf(String customer, User user) {
        return permissionsOf(user, findRole(customer, user.getRoleId()));
    }

    /** {@code role} is the user's role if they hold one and it still exists. */
    public Set<String> permissionsOf(User user, PermissionRole role) {
        Set<String> keys = new TreeSet<>();
        if (user.getRoleId() != null && role != null) {
            if (role.getPermissionKeys() != null) keys.addAll(role.getPermissionKeys());
            return keys;
        }
        Role profile = user.getActiveProfile();
        if (profile == Role.ADMIN || profile == Role.STAFF) {
            Permission legacy = user.effectivePermission();
            if (legacy.canRead()) keys.add(READ);
            if (legacy.canModify()) keys.addAll(Set.of(CREATE, UPDATE, DELETE));
        }
        return keys;
    }

    /** The permission an /admin request needs: by HTTP method, GET/HEAD read, POST create, DELETE delete, anything else (PUT, PATCH) update. */
    public static String requiredFor(String method) {
        return switch (method.toUpperCase()) {
            case "GET", "HEAD" -> READ;
            case "POST" -> CREATE;
            case "DELETE" -> DELETE;
            default -> UPDATE;
        };
    }

    /** The old READ/MODIFY/BOTH/NONE view of a key set, kept in /auth/verify for consumers that already read it: any write permission counts as modify. */
    public static Permission legacyPermission(Set<String> keys) {
        boolean read = keys.contains(READ);
        boolean modify = keys.contains(CREATE) || keys.contains(UPDATE) || keys.contains(DELETE);
        return read && modify ? Permission.BOTH : read ? Permission.READ : modify ? Permission.MODIFY : Permission.NONE;
    }
}
