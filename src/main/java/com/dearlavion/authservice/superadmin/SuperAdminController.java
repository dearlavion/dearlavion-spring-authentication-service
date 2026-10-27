package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.ApprovalStatus;
import com.dearlavion.authservice.user.model.Permission;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.model.User;
import com.dearlavion.authservice.user.request.UserVoRequest;
import com.dearlavion.authservice.user.response.UserPage;
import com.dearlavion.authservice.user.response.UserView;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Cross-project management for the security dashboard. Every route is behind {@link SuperAdminAuthFilter}. Unlike
 * /admin/users, the tenant is a path variable here: the superadmin's own token is scoped to the security tenant, and
 * the whole point is to act on the others (always checked against the CUSTOMERS allowlist by TenantService).
 */
@RestController
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class SuperAdminController {

    private static final List<Role> ADMIN_ROLES = List.of(Role.ADMIN, Role.STAFF);
    private static final int MAX_PAGE_SIZE = 100;

    public record ProjectSummary(String customer, long admins, long users, long pending) {}
    public record PendingAdmin(String customer, UserView user) {}
    public record ProjectUser(String customer, UserView user) {}
    public record ProjectUserPage(List<ProjectUser> items, long total, int page, int size) {}
    public record ApprovalRequest(ApprovalStatus status, Permission permission) {}
    public record CreateUserRequest(String username, String email, String password, String firstname, String lastname,
                                    Role role, Permission permission) {}

    private static final Pattern USERNAME = Pattern.compile("^[a-zA-Z0-9_.-]{3,40}$");

    private final UserService userService;
    private final TenantService tenants;
    private final AuditLog audit;

    @GetMapping("/projects")
    public List<ProjectSummary> projects() {
        return tenants.customers().stream()
                .filter(c -> !tenants.isSecurityTenant(c))
                .map(c -> new ProjectSummary(c,
                        userService.count(c, ADMIN_ROLES, null),
                        userService.count(c, List.of(Role.USER), null),
                        userService.count(c, ADMIN_ROLES, ApprovalStatus.PENDING)))
                .toList();
    }

    /** {@code role} is ADMIN (ADMIN and STAFF together) or USER; omitted means everyone. */
    @GetMapping("/projects/{customer}/users")
    public UserPage users(@PathVariable String customer,
                          @RequestParam(required = false) String role,
                          @RequestParam(required = false) ApprovalStatus status,
                          @RequestParam(required = false) String q,
                          @RequestParam(defaultValue = "0") int page,
                          @RequestParam(defaultValue = "20") int size) {
        tenants.assertCustomer(customer);
        int pageSize = Math.max(1, Math.min(size, MAX_PAGE_SIZE));
        int pageIndex = Math.max(0, page);
        List<Role> roles = roles(role);
        List<UserView> items = userService.search(customer, roles, status, q, pageIndex, pageSize).stream().map(userService::toView).toList();
        return new UserPage(items, userService.countMatching(customer, roles, status, q), pageIndex, pageSize);
    }

    /**
     * Users across projects (or one, with {@code customer}), ordered by project then username. Each project is its own
     * database, so the page is cut from per-project counts: only the projects the page actually touches are read.
     */
    @GetMapping("/users")
    public ProjectUserPage allUsers(@RequestParam(required = false) String customer,
                                    @RequestParam(required = false) String role,
                                    @RequestParam(required = false) String q,
                                    @RequestParam(defaultValue = "0") int page,
                                    @RequestParam(defaultValue = "20") int size) {
        List<String> projects;
        if (customer == null || customer.isBlank()) {
            projects = tenants.projects();
        } else {
            tenants.assertCustomer(customer);
            if (tenants.isSecurityTenant(customer)) throw new BadRequestException("Not a project");
            projects = List.of(customer);
        }
        int pageSize = Math.max(1, Math.min(size, MAX_PAGE_SIZE));
        int pageIndex = Math.max(0, page);
        List<Role> roles = roles(role);

        long total = 0;
        long[] counts = new long[projects.size()];
        for (int i = 0; i < counts.length; i++) {
            counts[i] = userService.countMatching(projects.get(i), roles, null, q);
            total += counts[i];
        }
        List<ProjectUser> items = new ArrayList<>();
        for (ProjectPaging.Segment s : ProjectPaging.plan(projects, counts, pageIndex, pageSize)) {
            userService.search(s.project(), roles, null, q, s.skip(), s.take())
                    .forEach(u -> items.add(new ProjectUser(s.project(), userService.toView(u))));
        }
        return new ProjectUserPage(items, total, pageIndex, pageSize);
    }

    @GetMapping("/approvals")
    public List<PendingAdmin> approvals() {
        List<PendingAdmin> pending = new ArrayList<>();
        for (String customer : tenants.customers()) {
            if (tenants.isSecurityTenant(customer)) continue;
            userService.search(customer, ADMIN_ROLES, ApprovalStatus.PENDING, null, 0, MAX_PAGE_SIZE)
                    .forEach(u -> pending.add(new PendingAdmin(customer, userService.toView(u))));
        }
        return pending;
    }

    /** Creates an ADMIN (approved straight away, with the given permission) or a plain USER in a project. */
    @PostMapping("/projects/{customer}/users")
    public UserView create(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable String customer, @RequestBody CreateUserRequest body) {
        tenants.assertCustomer(customer);
        if (tenants.isSecurityTenant(customer)) throw new BadRequestException("Create users in a project, not in the security tenant");
        if (body == null) throw new BadRequestException("Nothing to create");
        if (body.role() != Role.ADMIN && body.role() != Role.USER) throw new BadRequestException("role must be ADMIN or USER");
        String username = body.username() == null ? "" : body.username().trim().toLowerCase();
        String email = body.email() == null ? "" : body.email().trim().toLowerCase();
        if (!USERNAME.matcher(username).matches()) throw new BadRequestException("Username must be 3-40 letters, numbers, dots, dashes or underscores");
        if (!email.contains("@")) throw new BadRequestException("A valid email is required");
        if (body.password() == null || body.password().length() < 8) throw new BadRequestException("Password must be at least 8 characters");
        if (body.role() == Role.ADMIN && body.permission() == null) throw new BadRequestException("Choose a permission for the admin");

        UserVoRequest vo = new UserVoRequest(username, body.firstname(), body.lastname(), email, null, body.password(), null, body.role(), null);
        User created = userService.createAsSuperadmin(customer, vo, body.role(), body.permission());
        audit.record(actor.username(), "CREATE", customer, username, null,
                body.role() + (body.role() == Role.ADMIN ? "/" + body.permission() : ""));
        return userService.toView(created);
    }

    /** Approve (with a permission), reject, or send an admin back to pending. Only ADMIN/STAFF accounts take part. */
    @PatchMapping("/projects/{customer}/users/{username}/approval")
    public UserView decide(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable String customer, @PathVariable String username, @RequestBody ApprovalRequest body) {
        tenants.assertCustomer(customer);
        if (body == null || body.status() == null) throw new BadRequestException("Status is required");
        if (body.status() == ApprovalStatus.APPROVED && body.permission() == null) {
            throw new BadRequestException("Choose READ, MODIFY or BOTH to approve an admin");
        }
        User target = userService.loadByUsernameOrThrow(customer, username);
        if (!ADMIN_ROLES.contains(target.getActiveProfile())) throw new BadRequestException("Only admin accounts need approval");
        String before = describe(target);
        User saved = userService.decide(customer, username, body.status(), body.permission());
        audit.record(actor.username(), "APPROVAL", customer, username, before, describe(saved));
        return userService.toView(saved);
    }

    @PatchMapping("/projects/{customer}/users/{username}/active")
    public UserView setActive(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                              @PathVariable String customer, @PathVariable String username, @RequestBody Map<String, Boolean> body) {
        tenants.assertCustomer(customer);
        User target = userService.loadByUsernameOrThrow(customer, username);
        if (target.getActiveProfile() == Role.SUPERADMIN) throw new BadRequestException("Superadmin accounts can't be changed here");
        boolean active = Boolean.TRUE.equals(body.get("active"));
        User saved = userService.setActive(customer, username, active);
        audit.record(actor.username(), active ? "ACTIVATE" : "DEACTIVATE", customer, username, String.valueOf(target.isActive()), String.valueOf(active));
        return userService.toView(saved);
    }

    @GetMapping("/audit")
    public List<AuditEntry> audit(@RequestParam(defaultValue = "50") int limit) {
        int n = Math.max(1, Math.min(limit, 200));
        return tenants.db(tenants.securityTenant()).find(Query.query(new Criteria())
                .with(Sort.by(Sort.Direction.DESC, "at")).limit(n), AuditEntry.class);
    }

    private static List<Role> roles(String role) {
        if (role == null || role.isBlank()) return List.of();
        return switch (role.trim().toUpperCase()) {
            case "ADMIN" -> ADMIN_ROLES;
            case "USER" -> List.of(Role.USER);
            default -> throw new BadRequestException("role must be ADMIN or USER");
        };
    }

    private static String describe(User u) {
        return u.effectiveStatus() + (u.getPermission() != null ? "/" + u.getPermission() : "");
    }
}
