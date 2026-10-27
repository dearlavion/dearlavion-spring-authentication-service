package com.dearlavion.authservice.security;

import com.dearlavion.authservice.common.exception.ApiError;
import com.dearlavion.authservice.user.model.Permission;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.model.User;
import com.dearlavion.authservice.user.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Guards /admin/** routes. Unlike store-engine-v2's AdminGuard (which calls this very kind of
 * service's own /auth/verify over HTTP), this runs inside the service that issues the tokens, so
 * it verifies locally: decode + check the Bearer JWT, look up the user in the token's own
 * `customer` claim (never a client-supplied header — the signed claim isn't attacker-controllable
 * the way a header would be), then require activeProfile ADMIN/STAFF.
 *
 * <p>Deliberately a plain Filter, not routed through Spring Security's authorizeHttpRequests —
 * this service has exactly one guarded route group, and reproducing store-engine-v2's own
 * 401-vs-403 status code precisely (both no-token and bad-token are 401; only a valid token with
 * the wrong role is 403) is far simpler done directly here than by fighting Spring Security's
 * default entry points and its /error-redispatch quirk (see store-engine-v2's own AuthenticationFilter
 * comment for what that quirk looks like).
 */
@Component
@RequiredArgsConstructor
public class AdminAuthFilter extends OncePerRequestFilter {

    private static final Set<Role> ADMIN_ROLES = Set.of(Role.ADMIN, Role.STAFF);
    public static final String ADMIN_USER_ATTRIBUTE = "adminUser";

    private final JwtTokenService jwtTokenService;
    private final UserService userService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // CORS preflight never carries credentials by design — browsers send it to ask "would the
        // real request be allowed" before attaching the Authorization header. Rejecting it here
        // (before CorsFilter gets a chance to answer) writes a 401 with no CORS headers at all,
        // which the browser reports as a CORS failure rather than the real auth error.
        if (!request.getServletPath().startsWith("/admin/") || HttpMethod.OPTIONS.matches(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            writeError(response, HttpStatus.UNAUTHORIZED, "Authentication required");
            return;
        }

        TokenClaims claims = jwtTokenService.verifyToken(header.substring(7));
        if (claims == null || claims.customer() == null) {
            writeError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            return;
        }

        User user = userService.findByUsername(claims.customer(), claims.username());
        if (user == null || !userService.canSignIn(user)) {
            writeError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            return;
        }
        if (!ADMIN_ROLES.contains(user.getActiveProfile())) {
            writeError(response, HttpStatus.FORBIDDEN, "Admin access required");
            return;
        }
        boolean reads = HttpMethod.GET.matches(request.getMethod()) || HttpMethod.HEAD.matches(request.getMethod());
        Permission permission = user.effectivePermission();
        if (reads ? !permission.canRead() : !permission.canModify()) {
            writeError(response, HttpStatus.FORBIDDEN, reads ? "Read permission required" : "Modify permission required");
            return;
        }

        request.setAttribute(ADMIN_USER_ATTRIBUTE, new AdminRequestUser(claims.username(), claims.customer()));
        filterChain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(new ApiError(status.value(), message, status.getReasonPhrase())));
    }
}
