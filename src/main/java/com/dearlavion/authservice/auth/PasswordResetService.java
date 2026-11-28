package com.dearlavion.authservice.auth;

import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Password reset by email. Superadmins (the security tenant) get the email from this service ({@link ResetMailer});
 * project tenants keep the RESET_PASSWORD event that notification-service consumes.
 */
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final int MIN_SUPERADMIN_PASSWORD = 8;
    /** At most one superadmin reset email per account in this window (per instance), so the form can't flood an inbox. */
    private static final Duration COOLDOWN = Duration.ofSeconds(60);

    private final UserService userService;
    private final JwtTokenService jwtTokenService;
    private final AuthService authService;
    private final TenantService tenants;
    private final ResetMailer mailer;
    private final ConcurrentMap<String, Instant> lastSent = new ConcurrentHashMap<>();

    /** Starts the reset flow. Silently does nothing if the email is unknown, so the response never
     * reveals whether an account exists. */
    public void initiateReset(String customer, String email) {
        if (email == null || email.isBlank()) throw new BadRequestException("Email is required");
        User user = userService.findByEmail(customer, email.trim());
        if (user == null) user = userService.findByEmail(customer, email.trim().toLowerCase(Locale.ROOT));
        if (user == null) return;
        String token = jwtTokenService.generatePasswordResetToken(user.getUsername(), customer, fingerprint(user));
        if (!tenants.isSecurityTenant(customer)) {
            authService.sendResetPasswordEvent(user, token);
        } else if (userService.canSignIn(user) && claimSendSlot(user.getUsername())) {
            mailer.send(user.getEmail(), user.getUsername(), token);
        }
    }

    /** Resets the password given a valid reset token. Throws 401 if the token is invalid, expired or already used.
     * The customer/tenant is taken from the token claim, so no header is needed here. */
    public void resetPassword(String token, String newPassword) {
        JwtTokenService.ResetClaims claims = jwtTokenService.validatePasswordResetToken(token);
        if (claims.customer() == null) throw invalid();
        boolean superadmin = tenants.isSecurityTenant(claims.customer());
        User user = userService.loadByUsernameOrThrow(claims.customer(), claims.username());
        // A superadmin link is always single-use; a project token without a fingerprint (v1/v2) is still accepted.
        if (claims.fingerprint() == null ? superadmin : !claims.fingerprint().equals(fingerprint(user))) throw invalid();
        if (superadmin && newPassword.length() < MIN_SUPERADMIN_PASSWORD) {
            throw new BadRequestException("Password must be at least " + MIN_SUPERADMIN_PASSWORD + " characters");
        }
        if (!userService.replacePassword(claims.customer(), user, newPassword)) throw invalid();
    }

    private boolean claimSendSlot(String username) {
        Instant now = Instant.now();
        Instant slot = lastSent.compute(username, (k, last) -> last == null || last.plus(COOLDOWN).isBefore(now) ? now : last);
        return slot == now;
    }

    private static UnauthorizedException invalid() {
        return new UnauthorizedException("Invalid or expired token");
    }

    private static String fingerprint(User user) {
        try {
            String hash = user.getPassword() == null ? "" : user.getPassword();
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(hash.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
