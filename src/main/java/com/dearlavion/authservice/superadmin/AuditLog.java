package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.tenant.TenantService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

/** Appends to the security tenant's audit_log collection. */
@Service
@RequiredArgsConstructor
public class AuditLog {

    private final TenantService tenants;

    public void record(String actor, String action, String customer, String target, String before, String after) {
        tenants.db(tenants.securityTenant()).insert(new AuditEntry(null, Instant.now(), actor, action, customer, target, before, after));
    }
}
