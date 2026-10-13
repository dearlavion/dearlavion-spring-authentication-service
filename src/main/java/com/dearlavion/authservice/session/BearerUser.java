package com.dearlavion.authservice.session;

import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.security.TokenClaims;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Resolves the calling user from a Bearer token: the signed token's own customer claim picks the tenant (never
 * a client header), the user must still exist and be active. Only tokens carrying a user id ({@code uid}) are
 * accepted, which also keeps password-reset tokens (same key, no uid) from acting as a login.
 */
@Component
@RequiredArgsConstructor
public class BearerUser {

    public record Caller(User user, String customer) {}

    private final JwtTokenService jwtTokenService;
    private final UserService userService;

    public Caller resolve(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException("Authentication required");
        }
        TokenClaims claims = jwtTokenService.verifyToken(authHeader.substring(7));
        if (claims == null || claims.customer() == null || claims.userId() == null) {
            throw new UnauthorizedException("Invalid or expired token");
        }
        User user = userService.findByUsername(claims.customer(), claims.username());
        if (user == null || !user.isActive() || !claims.userId().equals(user.getId())) {
            throw new UnauthorizedException("Invalid or expired token");
        }
        return new Caller(user, claims.customer());
    }
}
