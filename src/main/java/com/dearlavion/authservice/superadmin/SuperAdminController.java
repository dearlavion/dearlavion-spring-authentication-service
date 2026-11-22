package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.access.AccessService;
import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.ApprovalStatus;
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

    public record ProjectSummary(String customer, boolean enabled, long admins, long users, long pending) {}
    public record PendingAdmin(String customer, UserView user) {}
    public record ProjectUser(String customer, UserView user) {}
    public record ProjectUserPage(List<ProjectUser> items, long total, int page, int size) {}
    /** Approving needs a role (assigning it is the approval); rejecting or sending back to pending needs none. */
    public record ApprovalRequest(ApprovalStatus status, String roleId) {}
    public record CreateUserRequest(String username, String email, String password, String firstname, String lastname, String roleId) {}
    public record AssignRoleRequest(String roleId) {}

    private static final Pattern USERNAME = Pattern.compile("^[a-zA-Z0-9_.-]{3,40}$");

    private final UserService userService;
    private final TenantService tenants;
    private final AuditLog audit;
    private final AccessService access;

    @GetMapping("/projects")
    public List<ProjectSummary> projects() {
        return tenants.projects().stream().map(this::summary).toList();
    }

    /**
     * Switches a project's authentication on or off. While off, sign-in, sign-up, token refresh, /auth/verify and the
     * project's admin routes all answer 403 (or an invalid-token 401 for verify); this API still works on it.
     */
    @PatchMapping("/projects/{customer}/enabled")
    public ProjectSummary setEnabled(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                                     @PathVariable String customer, @RequestBody Map<String, Boolean> body) {
        tenants.assertCustomer(customer);
        if (tenants.isSecurityTenant(customer)) throw new BadRequestException("The security tenant can't be switched off");
        if (body == null || body.get("enabled") == null) throw new BadRequestException("enabled is required");
        boolean enabled = body.get("enabled");
        boolean before = tenants.isEnabled(customer);
        tenants.setEnabled(customer, enabled, actor.username());
        audit.record(actor.username(), enabled ? "PROJECT_ENABLE" : "PROJECT_DISABLE", customer, customer,
                before ? "enabled" : "disabled", enabled ? "enabled" : "disabled");
        return summary(customer);
    }

    private ProjectSummary summary(String customer) {
        return new ProjectSummary(customer, tenants.isEnabled(customer),
                userService.count(customer, ADMIN_ROLES, null),
                userService.count(customer, List.of(Role.USER), null),
                userService.count(customer, ADMIN_ROLES, ApprovalStatus.PENDING));
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
        List<UserView> items = userService.toViews(customer, userService.search(customer, roles, status, q, pageIndex, pageSize));
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
            List<UserView> views = userService.toViews(s.project(), userService.search(s.project(), roles, null, q, s.skip(), s.take()));
            views.forEach(v -> items.add(new ProjectUser(s.project(), v)));
        }
        return new ProjectUserPage(items, total, pageIndex, pageSize);
    }

    @GetMapping("/approvals")
    public List<PendingAdmin> approvals() {
        List<PendingAdmin> pending = new ArrayList<>();
        for (String customer : tenants.customers()) {
            if (tenants.isSecurityTenant(customer)) continue;
            userService.toViews(customer, userService.search(customer, ADMIN_ROLES, ApprovalStatus.PENDING, null, 0, MAX_PAGE_SIZE))
                    .forEach(v -> pending.add(new PendingAdmin(customer, v)));
        }
        return pending;
    }

    /** Creates an account with a role: an admin-type role is approved straight away, a user-type role makes a plain user. */
    @PostMapping("/projects/{customer}/users")
    public UserView create(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable String customer, @RequestBody CreateUserRequest body) {
        tenants.assertCustomer(customer);
        if (tenants.isSecurityTenant(customer)) throw new BadRequestException("Create users in a project, not in the security tenant");
        if (body == null) throw new BadRequestException("Nothing to create");
        String username = body.username() == null ? "" : body.username().trim().toLowerCase();
        String email = body.email() == null ? "" : body.email().trim().toLowerCase();
        if (!USERNAME.matcher(username).matches()) throw new BadRequestException("Username must be 3-40 letters, numbers, dots, dashes or underscores");
        if (!email.contains("@")) throw new BadRequestException("A valid email is required");
        if (body.password() == null || body.password().length() < 8) throw new BadRequestException("Password must be at least 8 characters");
        PermissionRole role = roleOrThrow(customer, body.roleId());

        UserVoRequest vo = new UserVoRequest(username, body.firstname(), body.lastname(), email, null, body.password(), null, role.getAccountType(), null);
        User created = userService.createAsSuperadmin(customer, vo, role);
        audit.record(actor.username(), "CREATE", customer, username, null, role.getName());
        return userService.toView(customer, created);
    }

    /** Approve (by giving a role), reject, or send an admin request back to pending. Only ADMIN/STAFF accounts take part. */
    @PatchMapping("/projects/{customer}/users/{username}/approval")
    public UserView decide(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                           @PathVariable String customer, @PathVariable String username, @RequestBody ApprovalRequest body) {
        tenants.assertCustomer(customer);
        if (body == null || body.status() == null) throw new BadRequestException("Status is required");
        User target = userService.loadByUsernameOrThrow(customer, username);
        if (!ADMIN_ROLES.contains(target.getActiveProfile())) throw new BadRequestException("Only admin accounts need approval");
        PermissionRole role = body.status() == ApprovalStatus.APPROVED ? roleOrThrow(customer, body.roleId()) : null;
        String before = describe(customer, target);
        User saved = role != null ? userService.assignRole(customer, username, role) : userService.holdRequest(customer, username, body.status());
        audit.record(actor.username(), "APPROVAL", customer, username, before, describe(customer, saved));
        return userService.toView(customer, saved);
    }

    /** Gives an existing account another role. Their access follows the role from then on. */
    @PatchMapping("/projects/{customer}/users/{username}/role")
    public UserView assignRole(@RequestAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE) SuperAdminRequestUser actor,
                               @PathVariable String customer, @PathVariable String username, @RequestBody AssignRoleRequest body) {
        tenants.assertCustomer(customer);
        User target = userService.loadByUsernameOrThrow(customer, username);
        if (target.getActiveProfile() == Role.SUPERADMIN) throw new BadRequestException("Superadmin accounts can't be changed here");
        PermissionRole role = roleOrThrow(customer, body == null ? null : body.roleId());
        String before = describe(customer, target);
        User saved = userService.assignRole(customer, username, role);
        audit.record(actor.username(), "ROLE_ASSIGN", customer, username, before, describe(customer, saved));
        return userService.toView(customer, saved);
    }

    private PermissionRole roleOrThrow(String customer, String roleId) {
        if (roleId == null || roleId.isBlank()) throw new BadRequestException("Choose a role");
        PermissionRole role = access.findRole(customer, roleId);
        if (role == null) throw new BadRequestException("That role doesn't exist in " + customer);
        return role;
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
        return userService.toView(customer, saved);
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

    private String describe(String customer, User u) {
        PermissionRole role = access.findRole(customer, u.getRoleId());
        return u.effectiveStatus() + (role != null ? "/" + role.getName() : "");
    }
}
