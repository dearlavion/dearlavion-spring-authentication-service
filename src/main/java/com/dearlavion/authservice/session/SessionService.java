package com.dearlavion.authservice.session;

import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.session.SessionDtos.ProfileView;
import com.dearlavion.authservice.session.SessionDtos.SessionResponse;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/** Cookie sessions: a short access token plus a rotating refresh token kept (hashed) in the tenant's database. */
@Service
@RequiredArgsConstructor
public class SessionService {

    /** The JSON body plus the raw refresh token destined for the cookie. */
    public record Session(SessionResponse response, String refreshToken) {}

    private static final SecureRandom RANDOM = new SecureRandom();

    private final TenantService tenants;
    private final JwtTokenService jwtTokenService;

    @Value("${app.session-access-ttl-seconds}")
    private long accessTtlSeconds;

    @Value("${app.session-refresh-ttl-days}")
    private long refreshTtlDays;

    public Duration refreshTtl() {
        return Duration.ofDays(refreshTtlDays);
    }

    public Session start(User user, String customer) {
        String raw = newOpaqueToken();
        tenants.db(customer).insert(new RefreshToken(user.getId(), sha256(raw), Instant.now().plus(refreshTtl())));
        String token = jwtTokenService.generateToken(user.getUsername(), customer, user.getId(), accessTtlSeconds);
        return new Session(new SessionResponse(token, accessTtlSeconds, profile(user, customer)), raw);
    }

    /** Rotates: the presented token is revoked and a new session issued. */
    public Session refresh(String rawRefreshToken, String customer) {
        var db = tenants.db(customer);
        RefreshToken token = db.findOne(Query.query(Criteria.where("tokenHash").is(sha256(rawRefreshToken))), RefreshToken.class);
        if (token == null || !token.isActive()) throw new UnauthorizedException("Session expired, please log in again");
        token.revoke();
        db.save(token);
        User user = db.findById(token.getUserId(), User.class);
        if (user == null || !user.isActive() || !user.isApproved()) throw new UnauthorizedException("Session expired, please log in again");
        return start(user, customer);
    }

    public void logout(String rawRefreshToken, String customer) {
        var db = tenants.db(customer);
        RefreshToken token = db.findOne(Query.query(Criteria.where("tokenHash").is(sha256(rawRefreshToken))), RefreshToken.class);
        if (token != null) {
            token.revoke();
            db.save(token);
        }
    }

    public ProfileView profile(User u, String customer) {
        return new ProfileView(u.getId(), u.getUsername(), u.getEmail(), u.getFirstname(), u.getLastname(),
                u.getBio(), u.getImage(), u.getActiveProfile(), customer);
    }

    static String newOpaqueToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
