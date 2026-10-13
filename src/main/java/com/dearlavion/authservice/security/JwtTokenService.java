package com.dearlavion.authservice.security;

import com.dearlavion.authservice.common.exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Issues and verifies JWTs, byte-compatible with the original Java v1 JwtService and the NestJS
 * v2 JwtService: HS256, key = the base64-decoded secret, login token payload
 * {@code {username, customer, sub: username, iat, exp}}, reset token payload
 * {@code {sub: username, customer, type: 'PASSWORD_RESET', iat, exp}}. Using the same key +
 * algorithm + claim shape across all three stacks means tokens issued by any one of them verify
 * on any of the others.
 */
@Service
public class JwtTokenService {

    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_CUSTOMER = "customer";
    private static final String CLAIM_USER_ID = "uid";
    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_PASSWORD_RESET = "PASSWORD_RESET";

    private final Key key;
    private final long expiresInSeconds;
    private final long resetExpiresInSeconds;

    public JwtTokenService(
            @Value("${app.jwt-secret-base64}") String secretBase64,
            @Value("${app.jwt-expires-in-seconds}") long expiresInSeconds,
            @Value("${app.jwt-reset-expires-in-seconds}") long resetExpiresInSeconds
    ) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretBase64));
        this.expiresInSeconds = expiresInSeconds;
        this.resetExpiresInSeconds = resetExpiresInSeconds;
    }

    /** Login token, stamped with the caller's customer/tenant. */
    public String generateToken(String username, String customer) {
        return generateToken(username, customer, null, expiresInSeconds);
    }

    /**
     * Login token that also carries the user's id ({@code uid}, ignored by v1/v2 verification) and a
     * caller-chosen lifetime, so a session can use a short-lived access token plus a refresh token.
     */
    public String generateToken(String username, String customer, String userId, long ttlSeconds) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_USERNAME, username);
        claims.put(CLAIM_CUSTOMER, customer);
        if (userId != null) claims.put(CLAIM_USER_ID, userId);
        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + ttlSeconds * 1000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Verify a login token and return its claims, or null if invalid/expired. */
    public TokenClaims verifyToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            String username = claims.getSubject() != null ? claims.getSubject() : claims.get(CLAIM_USERNAME, String.class);
            if (username == null) return null;
            return new TokenClaims(username, claims.get(CLAIM_CUSTOMER, String.class), claims.get(CLAIM_USER_ID, String.class));
        } catch (Exception e) {
            return null;
        }
    }

    public String generatePasswordResetToken(String username, String customer) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .claim(CLAIM_TYPE, TYPE_PASSWORD_RESET)
                .claim(CLAIM_CUSTOMER, customer)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + resetExpiresInSeconds * 1000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Validates a reset token and returns its username + customer, or throws 401. */
    public TokenClaims validatePasswordResetToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid or expired token");
        }
        if (!TYPE_PASSWORD_RESET.equals(claims.get(CLAIM_TYPE, String.class))) {
            throw new UnauthorizedException("Invalid token type");
        }
        return new TokenClaims(claims.getSubject(), claims.get(CLAIM_CUSTOMER, String.class));
    }
}
