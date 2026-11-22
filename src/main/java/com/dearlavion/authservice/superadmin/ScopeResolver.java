package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.tenant.TenantService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Roles and permissions come in two scopes: the defaults every project inherits ({@link TenantService#DEFAULTS}) and a single
 * project's own. A path without a customer means the defaults. This turns that, and the list filters, into scope names.
 */
@Component
@RequiredArgsConstructor
public class ScopeResolver {

    public static final String DEFAULTS = TenantService.DEFAULTS;

    private final TenantService tenants;

    /** A request's scope: the defaults when no customer is given, else that project (never the security tenant). */
    public String scope(String customer) {
        if (customer == null || customer.isBlank()) return DEFAULTS;
        tenants.assertCustomer(customer);
        if (tenants.isSecurityTenant(customer)) throw new BadRequestException("Not a project");
        return customer;
    }

    /** What a list shows: everything, only the defaults ({@code *}), or the defaults plus one project's own. */
    public List<String> listScopes(String customer) {
        if (customer == null || customer.isBlank()) return allScopes();
        if (DEFAULTS.equals(customer)) return List.of(DEFAULTS);
        return List.of(DEFAULTS, scope(customer));
    }

    public List<String> allScopes() {
        List<String> scopes = new ArrayList<>();
        scopes.add(DEFAULTS);
        scopes.addAll(tenants.projects());
        return scopes;
    }

    /** The scopes whose names must not clash with {@code scope}: the defaults clash with every project, a project with the defaults and itself. */
    public List<String> peers(String scope) {
        return DEFAULTS.equals(scope) ? allScopes() : List.of(DEFAULTS, scope);
    }

    public MongoTemplate db(String scope) {
        return tenants.scopeDb(scope);
    }

    /** How a scope reads in the audit log and the API: {@code null} customer for the defaults. */
    public String customerOf(String scope) {
        return DEFAULTS.equals(scope) ? null : scope;
    }

    public String label(String scope) {
        return DEFAULTS.equals(scope) ? "defaults" : scope;
    }
}
