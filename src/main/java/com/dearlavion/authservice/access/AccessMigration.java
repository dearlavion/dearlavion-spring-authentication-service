package com.dearlavion.authservice.access;

import com.dearlavion.authservice.superadmin.PermissionRole;
import com.dearlavion.authservice.tenant.TenantService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * The generic {@code modify} permission was split into {@code create}, {@code update} and {@code delete}. At startup, every role
 * (the defaults and each project's) that still links {@code modify} gets the three in its place, and the old catalog entry is removed.
 * Idempotent, so it costs a couple of cheap queries on later starts. A failure is logged and retried on the next start rather than
 * stopping the service.
 */
@Component
@RequiredArgsConstructor
public class AccessMigration implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AccessMigration.class);
    private static final String OLD = "modify";

    private final TenantService tenants;

    @Override
    public void run(ApplicationArguments args) {
        try {
            migrate();
        } catch (RuntimeException e) {
            log.warn("Could not migrate the old 'modify' permission; it will be retried on the next start", e);
        }
    }

    public void migrate() {
        List<MongoTemplate> dbs = new ArrayList<>();
        dbs.add(tenants.defaultsDb());
        tenants.projects().forEach(p -> dbs.add(tenants.rawDb(p)));
        for (MongoTemplate db : dbs) {
            Query linked = Query.query(Criteria.where("permissionKeys").is(OLD));
            if (db.exists(linked, PermissionRole.class)) {
                // Two updates: Mongo won't add to and pull from the same array in one.
                db.updateMulti(linked, new Update().addToSet("permissionKeys").each("create", "update", "delete"), PermissionRole.class);
                db.updateMulti(Query.query(Criteria.where("permissionKeys").is(OLD)), new Update().pull("permissionKeys", OLD), PermissionRole.class);
            }
            db.remove(Query.query(Criteria.where("key").is(OLD)), PermissionDef.class);
        }
    }
}
