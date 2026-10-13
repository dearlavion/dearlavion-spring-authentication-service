package com.dearlavion.authservice.session;

import com.dearlavion.authservice.auth.AuthService;
import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.session.SessionDtos.SessionResponse;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.AuthType;
import com.dearlavion.authservice.user.model.User;
import com.dearlavion.authservice.user.request.UserVoRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Cookie sessions for browser apps (a short access token in the body, a rotating refresh token in an httpOnly,
 * SameSite=Strict cookie). Additive: POST /auth/login and its 24h token are unchanged for existing consumers.
 * Like the other credential endpoints, the tenant comes from the X-Customer header.
 */
@RestController
@RequestMapping("/auth/session")
@RequiredArgsConstructor
public class SessionController {

    private final AuthService authService;
    private final SessionService sessions;
    private final TenantService tenants;

    @Value("${app.session-cookie-name}")
    private String cookieName;

    @Value("${app.session-cookie-path}")
    private String cookiePath;

    @Value("${app.session-cookie-secure}")
    private boolean cookieSecure;

    @PostMapping("/login")
    public ResponseEntity<SessionResponse> login(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @RequestBody UserVoRequest request
    ) {
        tenants.assertCustomer(customer);
        User user = authService.resolve(AuthType.SIMPLE).authenticate(request, customer);
        if (!user.isActive()) throw new UnauthorizedException("Account is deactivated");
        return withCookie(sessions.start(user, customer));
    }

    @PostMapping("/refresh")
    public ResponseEntity<SessionResponse> refresh(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @CookieValue(name = "${app.session-cookie-name}", required = false) String token
    ) {
        tenants.assertCustomer(customer);
        if (token == null || token.isBlank()) throw new UnauthorizedException("Session expired, please log in again");
        return withCookie(sessions.refresh(token, customer));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @CookieValue(name = "${app.session-cookie-name}", required = false) String token
    ) {
        tenants.assertCustomer(customer);
        if (token != null && !token.isBlank()) sessions.logout(token, customer);
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO).toString()).build();
    }

    private ResponseEntity<SessionResponse> withCookie(SessionService.Session session) {
        return ResponseEntity.status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, cookie(session.refreshToken(), sessions.refreshTtl()).toString())
                .body(session.response());
    }

    private ResponseCookie cookie(String value, Duration maxAge) {
        return ResponseCookie.from(cookieName, value)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path(cookiePath)
                .maxAge(maxAge)
                .build();
    }
}
