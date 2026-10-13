package com.dearlavion.authservice.session;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/**
 * A cookie session's refresh token. Only its SHA-256 hash is stored (the raw value lives in an httpOnly
 * cookie), and Mongo purges it once {@code expiresAt} passes. Lives in the tenant's own database.
 */
@Document("refresh_tokens")
public class RefreshToken {

    @Id
    private String id;
    private String userId;
    private String tokenHash;
    private Instant expiresAt;
    private Instant revokedAt;

    protected RefreshToken() {}

    public RefreshToken(String userId, String tokenHash, Instant expiresAt) {
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }

    public String getUserId() { return userId; }

    public boolean isActive() {
        return revokedAt == null && expiresAt.isAfter(Instant.now());
    }

    public void revoke() {
        if (revokedAt == null) revokedAt = Instant.now();
    }
}
