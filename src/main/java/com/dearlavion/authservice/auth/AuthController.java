package com.dearlavion.authservice.auth;

import com.dearlavion.authservice.auth.request.ResetPasswordRequest;
import com.dearlavion.authservice.auth.request.UpdateEmailRequest;
import com.dearlavion.authservice.auth.request.VerifyGoogleRequest;
import com.dearlavion.authservice.auth.request.VerifyRequest;
import com.dearlavion.authservice.auth.response.LoginResponse;
import com.dearlavion.authservice.auth.response.LoginUserView;
import com.dearlavion.authservice.auth.response.VerifyResult;
import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.security.TokenClaims;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.AuthType;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.model.User;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.request.UserVoRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthService authService;
    private final JwtTokenService jwtTokenService;
    private final PasswordResetService passwordResetService;
    private final GoogleVerifierService googleVerifier;
    private final AuthMapper authMapper;
    private final TenantService tenants;

    @Value("${app.google-enabled}")
    private boolean googleEnabled;

    @Value("${app.provision-secret}")
    private String provisionSecret;

    @Value("${app.jwt-expires-in-seconds}")
    private long jwtExpiresInSeconds;

    /** Privileged-role assignment is allowed only with a matching X-Provision-Secret (fail closed
     * if no secret is configured). Keeps the public signup endpoint from self-granting admin. */
    private boolean canProvision(String secret) {
        return provisionSecret != null && !provisionSecret.isBlank() && provisionSecret.equals(secret);
    }

    /** The role a caller may actually be given: privileged ones need the provision secret, and SUPERADMIN additionally
     * only exists in the security tenant. Anything else falls back to USER. */
    private Role grantableRole(Role wanted, String customer, String secret) {
        if (wanted == null || !canProvision(secret)) return Role.USER;
        if (wanted == Role.SUPERADMIN) return tenants.isSecurityTenant(customer) ? Role.SUPERADMIN : Role.USER;
        return wanted;
    }

    private AuthType parseType(String typeParam) {
        if (typeParam == null || typeParam.isBlank()) return AuthType.SIMPLE;
        try {
            return AuthType.valueOf(typeParam.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Unsupported login type");
        }
    }

    @PostMapping("/register")
    public Map<String, String> register(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @RequestBody UserVoRequest request,
            @RequestHeader(value = "X-Provision-Secret", required = false) String provisionSecretHeader,
            @RequestParam(value = "type", required = false) String typeParam,
            @RequestParam(value = "googleToken", required = false) String googleToken
    ) {
        AuthType type = googleEnabled ? parseType(typeParam) : AuthType.SIMPLE;
        if (type == AuthType.GOOGLE && googleToken != null) request = request.withGoogleToken(googleToken);

        request = request.withActiveProfile(grantableRole(request.activeProfile(), customer, provisionSecretHeader));

        AuthStrategy strategy = authService.resolve(type);
        User user = strategy.register(request, customer);
        authService.sendNewUserWelcomeEmail(user);
        return Map.of("message", "User registered successfully", "user", user.getUsername());
    }

    @PatchMapping("/user/{username}")
    public Map<String, String> updateUser(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @PathVariable String username,
            @RequestBody UserVoRequest u,
            @RequestHeader(value = "X-Provision-Secret", required = false) String provisionSecretHeader
    ) {
        // Role changes are gated by the same secret; without it, ignore any activeProfile in the
        // body (other profile fields still update).
        if (u.activeProfile() != null) {
            Role granted = canProvision(provisionSecretHeader) ? grantableRole(u.activeProfile(), customer, provisionSecretHeader) : null;
            // A role the caller may not grant (SUPERADMIN outside the security tenant) is ignored, not downgraded.
            u = u.withActiveProfile(granted == Role.USER && u.activeProfile() != Role.USER ? null : granted);
        }
        User updated = userService.updateUser(customer, username, u);
        return Map.of("message", "User updated successfully", "username", updated.getUsername());
    }

    @GetMapping("/user/{username}")
    public com.dearlavion.authservice.user.response.UserView getUser(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @PathVariable String username
    ) {
        User user = userService.loadByUsernameOrThrow(customer, username);
        return userService.toView(user);
    }

    /** Self-service: update the CALLING user's own email. Unlike PATCH /auth/user/{username}
     * above (an internal, service-to-service endpoint — no bearer check, trusts the path
     * username as-is), this resolves the target user from the caller's own verified JWT, never
     * from client input, so an authenticated caller can only ever edit their own account. */
    @PatchMapping("/me")
    public com.dearlavion.authservice.user.response.UserView updateMe(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody UpdateEmailRequest body
    ) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException("Authentication required");
        }
        TokenClaims claims = jwtTokenService.verifyToken(authHeader.substring(7));
        if (claims == null || claims.customer() == null) {
            throw new UnauthorizedException("Invalid or expired token");
        }
        if (body == null || body.email() == null || body.email().isBlank()) {
            throw new BadRequestException("Email is required");
        }
        User updated = userService.updateUser(claims.customer(), claims.username(),
                new UserVoRequest(null, null, null, body.email(), null, null, null, null, null));
        return userService.toView(updated);
    }

    /** Public request for admin access to a project: created as a PENDING ADMIN that cannot sign in until a superadmin approves
     * it and picks a permission. Needs no provision secret, which is exactly why it grants nothing by itself. */
    @PostMapping("/admin-request")
    public Map<String, String> requestAdmin(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @RequestBody UserVoRequest request
    ) {
        if (request == null || isBlank(request.username()) || isBlank(request.email()) || isBlank(request.password())) {
            throw new BadRequestException("Username, email and password are required");
        }
        if (tenants.isSecurityTenant(customer)) throw new BadRequestException("Admin requests are for project tenants");
        User user = userService.registerAdminRequest(customer, request);
        return Map.of("message", "Request received, a superadmin will review it", "user", user.getUsername());
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    @PostMapping("/login")
    public LoginResponse login(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @RequestBody UserVoRequest request,
            @RequestParam(value = "type", required = false) String typeParam
    ) {
        AuthType type = googleEnabled ? parseType(typeParam) : AuthType.SIMPLE;
        AuthStrategy strategy = authService.resolve(type);
        User user = strategy.authenticate(request, customer);
        userService.assertCanSignIn(user);
        String token = jwtTokenService.generateToken(user.getUsername(), customer, user.getId(), jwtExpiresInSeconds);
        return new LoginResponse(token, authMapper.toLoginUserView(user, customer));
    }

    @PostMapping("/forgot-password")
    public Map<String, String> forgotPassword(
            @RequestHeader(value = "X-Customer", required = false) String customer,
            @RequestParam String email
    ) {
        passwordResetService.initiateReset(customer, email);
        return Map.of("message", "If an account exists, a reset link was sent.");
    }

    @PostMapping("/reset-password")
    public Map<String, String> resetPassword(@RequestBody ResetPasswordRequest body) {
        if (body == null || body.token() == null || body.token().isBlank()
                || body.newPassword() == null || body.newPassword().isBlank()) {
            throw new BadRequestException("Invalid or expired token");
        }
        try {
            passwordResetService.resetPassword(body.token(), body.newPassword());
        } catch (Exception e) {
            throw new BadRequestException("Invalid or expired token");
        }
        return Map.of("message", "Password reset successful");
    }

    @PostMapping("/verify")
    public VerifyResult verify(@RequestBody VerifyRequest req) {
        String token = req != null ? req.token() : null;
        if (token == null || token.isBlank()) {
            throw new BadRequestException("Token missing", Map.of("valid", false, "error", "Token missing"));
        }
        TokenClaims claims = jwtTokenService.verifyToken(token);
        if (claims == null || claims.customer() == null) {
            throw new UnauthorizedException("Invalid token", Map.of("valid", false));
        }
        User user;
        try {
            user = userService.findByUsername(claims.customer(), claims.username());
        } catch (Exception e) {
            user = null;
        }
        if (user == null || !userService.canSignIn(user)) {
            throw new UnauthorizedException("Invalid token", Map.of("valid", false));
        }
        // activeProfile (role) and customer (tenant) are additive — existing consumers ignore
        // them; store-engine uses the role for admin authz and the customer for tenant enforcement.
        return new VerifyResult(true, claims.username(), user.getEmail(), user.getId(), user.getActiveProfile(), claims.customer(),
                user.effectivePermission());
    }

    @PostMapping("/verify-google")
    public Map<String, String> verifyGoogle(@RequestBody VerifyGoogleRequest body) {
        if (body == null || body.idToken() == null || body.idToken().isBlank()) {
            throw new BadRequestException("Google token missing");
        }
        GoogleIdToken.Payload payload = googleVerifier.verify(body.idToken());
        return Map.of("email", payload.getEmail());
    }
}
