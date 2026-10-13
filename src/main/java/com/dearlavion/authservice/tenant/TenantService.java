package com.dearlavion.authservice.tenant;

import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.session.RefreshToken;
import com.dearlavion.authservice.user.model.User;
import com.mongodb.client.MongoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.stereotype.Service;

import java.util.Arrays;
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
    private final ConcurrentMap<String, MongoTemplate> templates = new ConcurrentHashMap<>();

    public TenantService(MongoClient mongoClient, @Value("${app.customers}") String customersCsv) {
        this.mongoClient = mongoClient;
        this.allowedCustomers = Arrays.stream(customersCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    /** Throw 400 unless the customer is in the allowlist. Returns it for convenient chaining. */
    public String assertCustomer(String customer) {
        if (customer == null || customer.isBlank() || !allowedCustomers.contains(customer)) {
            throw new BadRequestException("Unknown customer: " + (customer == null || customer.isBlank() ? "(none)" : customer));
        }
        return customer;
    }

    /** The MongoTemplate bound to a customer's isolated database, building the unique
     * username/email indexes the first time it's touched (cached, so at most once per customer). */
    public MongoTemplate db(String customer) {
        assertCustomer(customer);
        return templates.computeIfAbsent(customer, c -> {
            MongoTemplate template = new MongoTemplate(mongoClient, "authentication-" + c);
            template.indexOps(User.class).ensureIndex(new Index().on("username", Sort.Direction.ASC).unique());
            template.indexOps(User.class).ensureIndex(new Index().on("email", Sort.Direction.ASC).unique());
            // Refresh tokens: looked up by hash, purged by Mongo once expired.
            template.indexOps(RefreshToken.class).ensureIndex(new Index().on("tokenHash", Sort.Direction.ASC).unique());
            template.indexOps(RefreshToken.class).ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC).expire(0));
            return template;
        });
    }
}
