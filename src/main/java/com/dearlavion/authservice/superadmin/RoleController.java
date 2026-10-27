package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.common.exception.ConflictException;
import com.dearlavion.authservice.common.exception.NotFoundException;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.Permission;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Per-project permission presets for the security dashboard's Role menu. Behind {@link SuperAdminAuthFilter} like the rest of /superadmin. */
@RestController
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class RoleController {

    private static final int MAX_PAGE_SIZE = 100;

    public record CreateRoleRequest(String name, String description, Permission permission) {}
    public record RoleView(String id, String name, String description, Permission permission, String createdBy, Instant createdAt) {}
    public record ProjectRole(String customer, RoleView role) {}
    public record ProjectRolePage(List<ProjectRole> items, long total, int page, int size) {}

    private final TenantService tenants;
    private final AuditLog audit;

    @PostMapping("/projects/{customer}/roles")
    public RoleView create(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable String customer, @RequestBody CreateRoleRequest body) {
        project(customer);
        if (body == null) throw new BadRequestException("Nothing to create");
        String name = body.name() == null ? "" : body.name().trim();
        String description = body.description() == null ? null : body.description().trim();
        if (name.length() < 2 || name.length() > 60) throw new BadRequestException("Name must be 2-60 characters");
        if (description != null && description.length() > 200) throw new BadRequestException("Description is too long (200 characters at most)");
        if (body.permission() == null || body.permission() == Permission.NONE) {
            throw new BadRequestException("Choose READ, MODIFY or BOTH for the role");
        }
        MongoTemplate db = tenants.db(customer);
        if (db.exists(Query.query(Criteria.where("name").regex("^" + Pattern.quote(name) + "$", "i")), PermissionRole.class)) {
            throw new ConflictException("A role named \"" + name + "\" already exists in " + customer);
        }
        try {
            PermissionRole saved = db.insert(new PermissionRole(null, name, description == null || description.isEmpty() ? null : description,
                    body.permission(), actor.username(), Instant.now()));
            audit.record(actor.username(), "ROLE_CREATE", customer, name, null, String.valueOf(body.permission()));
            return view(saved);
        } catch (DuplicateKeyException e) {
            throw new ConflictException("A role named \"" + name + "\" already exists in " + customer);
        }
    }

    /** Roles across projects (or one, with {@code customer}), ordered by project then name. */
    @GetMapping("/roles")
    public ProjectRolePage list(@RequestParam(required = false) String customer,
                                @RequestParam(required = false) String q,
                                @RequestParam(defaultValue = "0") int page,
                                @RequestParam(defaultValue = "20") int size) {
        List<String> projects = customer == null || customer.isBlank() ? tenants.projects() : List.of(project(customer));
        int pageSize = Math.max(1, Math.min(size, MAX_PAGE_SIZE));
        int pageIndex = Math.max(0, page);
        Criteria match = matching(q);

        long total = 0;
        long[] counts = new long[projects.size()];
        for (int i = 0; i < counts.length; i++) {
            counts[i] = tenants.db(projects.get(i)).count(Query.query(match), PermissionRole.class);
            total += counts[i];
        }
        List<ProjectRole> items = new ArrayList<>();
        for (ProjectPaging.Segment s : ProjectPaging.plan(projects, counts, pageIndex, pageSize)) {
            Query query = Query.query(match).with(Sort.by("name")).skip(s.skip()).limit(s.take());
            tenants.db(s.project()).find(query, PermissionRole.class).forEach(r -> items.add(new ProjectRole(s.project(), view(r))));
        }
        return new ProjectRolePage(items, total, pageIndex, pageSize);
    }

    @DeleteMapping("/projects/{customer}/roles/{id}")
    public Map<String, String> delete(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                                      @PathVariable String customer, @PathVariable String id) {
        project(customer);
        MongoTemplate db = tenants.db(customer);
        PermissionRole role = db.findById(id, PermissionRole.class);
        if (role == null) throw new NotFoundException("Role not found");
        db.remove(role);
        audit.record(actor.username(), "ROLE_DELETE", customer, role.getName(), String.valueOf(role.getPermission()), null);
        return Map.of("message", "Role deleted");
    }

    /** A project the superadmin may manage: an allowed customer other than the security tenant itself. */
    private String project(String customer) {
        tenants.assertCustomer(customer);
        if (tenants.isSecurityTenant(customer)) throw new BadRequestException("Not a project");
        return customer;
    }

    private static Criteria matching(String q) {
        if (q == null || q.isBlank()) return new Criteria();
        String pattern = ".*" + Pattern.quote(q.trim()) + ".*";
        return new Criteria().orOperator(Criteria.where("name").regex(pattern, "i"), Criteria.where("description").regex(pattern, "i"));
    }

    private static RoleView view(PermissionRole r) {
        return new RoleView(r.getId(), r.getName(), r.getDescription(), r.getPermission(), r.getCreatedBy(), r.getCreatedAt());
    }
}
