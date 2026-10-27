package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.common.exception.ApiError;
import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.security.TokenClaims;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.model.User;
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

/**
 * Guards /superadmin/**, the same way {@link com.dearlavion.authservice.security.AdminAuthFilter} guards /admin/**: the
 * Bearer token is verified locally and the tenant comes from its signed {@code customer} claim. Here the tenant must also
 * be the security tenant and the user a SUPERADMIN, so no project admin's token (whatever its role) can reach these routes.
 */
@Component
@RequiredArgsConstructor
public class SuperAdminAuthFilter extends OncePerRequestFilter {

    public static final String SUPERADMIN_ATTRIBUTE = "superAdminUser";

    private final JwtTokenService jwtTokenService;
    private final UserService userService;
    private final TenantService tenants;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // CORS preflight carries no credentials; see AdminAuthFilter.
        if (!request.getServletPath().startsWith("/superadmin/") || HttpMethod.OPTIONS.matches(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            writeError(response, HttpStatus.UNAUTHORIZED, "Authentication required");
            return;
        }
        TokenClaims claims = jwtTokenService.verifyToken(header.substring(7));
        if (claims == null || claims.customer() == null || claims.userId() == null) {
            writeError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            return;
        }
        if (!tenants.isSecurityTenant(claims.customer())) {
            writeError(response, HttpStatus.FORBIDDEN, "Superadmin access required");
            return;
        }
        User user = userService.findByUsername(claims.customer(), claims.username());
        if (user == null || !userService.canSignIn(user) || !claims.userId().equals(user.getId())) {
            writeError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            return;
        }
        if (user.getActiveProfile() != Role.SUPERADMIN) {
            writeError(response, HttpStatus.FORBIDDEN, "Superadmin access required");
            return;
        }
        request.setAttribute(SUPERADMIN_ATTRIBUTE, new SuperAdminRequestUser(user.getUsername()));
        filterChain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(new ApiError(status.value(), message, status.getReasonPhrase())));
    }
}
