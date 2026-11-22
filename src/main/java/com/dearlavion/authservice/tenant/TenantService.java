package com.dearlavion.authservice.tenant;

import com.dearlavion.authservice.access.PermissionDef;
import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.common.exception.ForbiddenException;
import com.dearlavion.authservice.session.RefreshToken;
import com.dearlavion.authservice.superadmin.PermissionRole;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.superadmin.SuperAdminAuthFilter;
import com.dearlavion.authservice.user.model.User;
import com.mongodb.client.MongoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * Resolves the per-customer {@link MongoTemplate}. Each customer's users live in an isolated
 * `authentication-<customer>` database on the same cluster. Deliberately NOT a MongoRepository —
 * repositories are bound to a single collection/database at bean-creation time, which can't
 * express "the database name is only known once the request's X-Customer header/JWT claim
 * arrives" — so all User CRUD in this service goes through {@code MongoTemplate} instances handed
 * out by this class instead. Templates (and their one-time unique-index setup) are cached per
 * customer so repeat requests don't redo either.
 */
@Service
public class TenantService {

    private final MongoClient mongoClient;
    private final Set<String> allowedCustomers;
    private final String securityTenant;
    private final ConcurrentMap<String, MongoTemplate> templates = new ConcurrentHashMap<>();

    /** A project's on/off flag, remembered briefly so the check doesn't read the security database on every call. */
    private record Flag(boolean enabled, long checkedAtMillis) {}

    /** The scope name for roles and permissions that apply to every project (they live in the security tenant's database). */
    public static final String DEFAULTS = "*";

    /** Built in to every deployment: they gate /admin/** by request type (GET read, POST create, PUT/PATCH update, DELETE delete). {key, description}. */
    private static final String[][] BUILT_IN_PERMISSIONS = {
            {"read", "View entries (GET)"},
            {"create", "Add new entries (POST)"},
            {"update", "Change existing entries (PUT/PATCH)"},
            {"delete", "Remove entries (DELETE)"},
    };

    /** Default roles every project can assign. {name, description, accountType, permission keys}. Admin and User are built in. */
    private static final Object[][] BUILT_IN_ROLES = {
            {"Admin", "Full access to a project's admin area", Role.ADMIN, List.of("read", "create", "update", "delete")},
            {"User", "A regular account with no admin access", Role.USER, List.<String>of()},
    };

    private static final long FLAG_TTL_MILLIS = 5_000;
    private final ConcurrentMap<String, Flag> flags = new ConcurrentHashMap<>();

    public TenantService(MongoClient mongoClient, @Value("${app.customers}") String customersCsv,
                         @Value("${app.security-tenant}") String securityTenant) {
        this.mongoClient = mongoClient;
        this.securityTenant = securityTenant;
        this.allowedCustomers = Arrays.stream(customersCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    /** The tenant that holds superadmin accounts; the only one allowed to carry the SUPERADMIN role. */
    public String securityTenant() {
        return securityTenant;
    }

    public boolean isSecurityTenant(String customer) {
        return securityTenant.equals(customer);
    }

    /** The customers that are real projects: everything but the security tenant, sorted. */
    public List<String> projects() {
        return customers().stream().filter(c -> !isSecurityTenant(c)).toList();
    }

    /** Every tenant this instance serves, sorted. */
    public List<String> customers() {
        return allowedCustomers.stream().sorted().toList();
    }

    /** Throw 400 unless the customer is in the allowlist. Returns it for convenient chaining. */
    public String assertCustomer(String customer) {
        if (customer == null || customer.isBlank() || !allowedCustomers.contains(customer)) {
            throw new BadRequestException("Unknown customer: " + (customer == null || customer.isBlank() ? "(none)" : customer));
        }
        return customer;
    }

    /**
     * The MongoTemplate bound to a customer's isolated database. Refuses (403) while the project's authentication is switched
     * off, which covers every sign-in, token, lookup and admin path at once since they all read users through here. Requests
     * from a superadmin are exempt (they have to be able to see and re-enable a disabled project), and so is the security
     * tenant itself.
     */
    public MongoTemplate db(String customer) {
        assertCustomer(customer);
        if (!isSecurityTenant(customer) && !isSuperadminRequest() && !isEnabled(customer)) {
            throw new ForbiddenException("Authentication is disabled for this project");
        }
        return template(customer);
    }

    /** Builds the unique username/email indexes the first time a customer is touched (cached, so at most once per customer). */
    private MongoTemplate template(String customer) {
        return templates.computeIfAbsent(customer, c -> {
            MongoTemplate template = new MongoTemplate(mongoClient, "authentication-" + c);
            template.indexOps(User.class).ensureIndex(new Index().on("username", Sort.Direction.ASC).unique());
            template.indexOps(User.class).ensureIndex(new Index().on("email", Sort.Direction.ASC).unique());
            template.indexOps(PermissionRole.class).ensureIndex(new Index().on("name", Sort.Direction.ASC).unique());
            template.indexOps(PermissionDef.class).ensureIndex(new Index().on("key", Sort.Direction.ASC).unique());
            if (isSecurityTenant(c)) {
                seedBuiltInPermissions(template);
                seedBuiltInRoles(template);
            }
            // Refresh tokens: looked up by hash, purged by Mongo once expired.
            template.indexOps(RefreshToken.class).ensureIndex(new Index().on("tokenHash", Sort.Direction.ASC).unique());
            template.indexOps(RefreshToken.class).ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC).expire(0));
            return template;
        });
    }

    private static void seedBuiltInPermissions(MongoTemplate template) {
        for (String[] p : BUILT_IN_PERMISSIONS) {
            if (template.exists(Query.query(Criteria.where("key").is(p[0])), PermissionDef.class)) continue;
            try {
                template.insert(new PermissionDef(null, p[0], p[1], true, "system", Instant.now()));
            } catch (DuplicateKeyException ignored) {
                // Another instance seeded it first.
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void seedBuiltInRoles(MongoTemplate template) {
        for (Object[] r : BUILT_IN_ROLES) {
            String name = (String) r[0];
            if (template.exists(Query.query(Criteria.where("name").is(name)), PermissionRole.class)) continue;
            try {
                template.insert(new PermissionRole(null, name, (String) r[1], (Role) r[2], new java.util.ArrayList<>((List<String>) r[3]),
                        true, "system", Instant.now()));
            } catch (DuplicateKeyException ignored) {
                // Another instance seeded it first.
            }
        }
    }

    /** A project's database without the on/off check, for service work that has to see every project (startup migrations). */
    public MongoTemplate rawDb(String customer) {
        assertCustomer(customer);
        return template(customer);
    }

    /** The database of default roles and permissions (the security tenant's), exempt from the per-project on/off check. */
    public MongoTemplate defaultsDb() {
        return template(securityTenant);
    }

    /** A scope is {@link #DEFAULTS} or a project; either way the caller must already be a superadmin or otherwise allowed. */
    public MongoTemplate scopeDb(String scope) {
        return DEFAULTS.equals(scope) ? defaultsDb() : db(scope);
    }

    private static boolean isSuperadminRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes != null && attributes.getAttribute(SuperAdminAuthFilter.SUPERADMIN_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST) != null;
    }

    /** Whether the project's authentication is on. A project nobody has switched off has no setting and counts as enabled. */
    public boolean isEnabled(String customer) {
        long now = System.currentTimeMillis();
        Flag cached = flags.get(customer);
        if (cached != null && now - cached.checkedAtMillis() < FLAG_TTL_MILLIS) return cached.enabled();
        ProjectSetting setting = template(securityTenant).findById(customer, ProjectSetting.class);
        boolean enabled = setting == null || setting.isEnabled();
        flags.put(customer, new Flag(enabled, now));
        return enabled;
    }

    /** Switches a project's authentication on or off. Takes effect at once on this instance; another instance picks it up within a few seconds. */
    public void setEnabled(String customer, boolean enabled, String updatedBy) {
        template(securityTenant).save(new ProjectSetting(customer, enabled, updatedBy, Instant.now()));
        flags.put(customer, new Flag(enabled, System.currentTimeMillis()));
    }
}
