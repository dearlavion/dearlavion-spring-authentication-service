package com.dearlavion.authservice.auth;

import com.dearlavion.authservice.common.exception.ForbiddenException;
import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.security.TokenClaims;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Who may call {@code /auth/user/{username}}: another backend (X-Service-Key), an operator (X-Provision-Secret), or the
 * user themselves (a login token for that username in that tenant). A secret that is not configured never matches.
 */
@Component
public class UserRouteGuard {

    private final JwtTokenService jwtTokenService;
    private final UserService userService;
    private final TenantService tenants;
    private final String serviceKey;
    private final String provisionSecret;

    public UserRouteGuard(JwtTokenService jwtTokenService, UserService userService, TenantService tenants,
                          @Value("${app.service-key}") String serviceKey,
                          @Value("${app.provision-secret}") String provisionSecret) {
        this.jwtTokenService = jwtTokenService;
        this.userService = userService;
        this.tenants = tenants;
        this.serviceKey = serviceKey;
        this.provisionSecret = provisionSecret;
    }

    /** 401 without a valid credential, 403 for a valid login token that belongs to someone else. */
    public void assertMayAccess(String customer, String username, String authHeader, String serviceKeyHeader,
                                String provisionSecretHeader) {
        tenants.assertCustomer(customer);
        if (matches(serviceKey, serviceKeyHeader) || matches(provisionSecret, provisionSecretHeader)) return;

        TokenClaims claims = authHeader != null && authHeader.startsWith("Bearer ")
                ? jwtTokenService.verifyToken(authHeader.substring(7)) : null;
        if (claims == null || claims.customer() == null) throw new UnauthorizedException("Authentication required");
        // Checked before any lookup, so the answer doesn't reveal whether the other account exists.
        if (!customer.equals(claims.customer()) || !username.equals(claims.username())) {
            throw new ForbiddenException("You can only access your own account");
        }
        User user = userService.findByUsername(customer, username);
        // v1/v2 tokens carry no uid; when there is one, it must be this account's.
        if (!userService.canSignIn(user) || (claims.userId() != null && !claims.userId().equals(user.getId()))) {
            throw new UnauthorizedException("Invalid or expired token");
        }
    }

    private static boolean matches(String expected, String given) {
        return expected != null && !expected.isBlank() && given != null
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), given.getBytes(StandardCharsets.UTF_8));
    }
}
