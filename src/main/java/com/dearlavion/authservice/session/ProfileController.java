package com.dearlavion.authservice.session;

import com.dearlavion.authservice.common.exception.BadRequestException;
import com.dearlavion.authservice.session.BearerUser.Caller;
import com.dearlavion.authservice.session.SessionDtos.LookupEntry;
import com.dearlavion.authservice.session.SessionDtos.LookupRequest;
import com.dearlavion.authservice.session.SessionDtos.PasswordCheckRequest;
import com.dearlavion.authservice.session.SessionDtos.ProfileUpdateRequest;
import com.dearlavion.authservice.session.SessionDtos.ProfileView;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.UserService;
import com.dearlavion.authservice.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Self-service for the CALLING user (resolved from their own verified token, never from client input), plus a
 * minimal id → name lookup for other backends that show people next to ids. All scoped to the token's tenant.
 */
@RestController
@RequiredArgsConstructor
public class ProfileController {

    private static final int MAX_LOOKUP = 200;
    private static final int MAX_NAME = 120;
    private static final int MAX_BIO = 2000;

    private final BearerUser bearer;
    private final UserService userService;
    private final TenantService tenants;
    private final SessionService sessions;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/auth/me")
    public ProfileView me(@RequestHeader(value = "Authorization", required = false) String auth) {
        Caller c = bearer.resolve(auth);
        return sessions.profile(c.user(), c.customer());
    }

    @PatchMapping("/auth/me/profile")
    public ProfileView updateProfile(@RequestHeader(value = "Authorization", required = false) String auth,
                                     @RequestBody ProfileUpdateRequest body) {
        Caller c = bearer.resolve(auth);
        if (body == null) throw new BadRequestException("Nothing to update");
        if (tooLong(body.firstname(), MAX_NAME) || tooLong(body.lastname(), MAX_NAME) || tooLong(body.bio(), MAX_BIO)) {
            throw new BadRequestException("Name or bio is too long");
        }
        User user = c.user();
        if (body.firstname() != null) user.setFirstname(body.firstname().trim());
        if (body.lastname() != null) user.setLastname(body.lastname().trim());
        if (body.bio() != null) user.setBio(body.bio().isBlank() ? null : body.bio().trim());
        tenants.db(c.customer()).save(user);
        return sessions.profile(user, c.customer());
    }

    /** Lets a backend re-check the caller's password (e.g. before deleting something) without issuing a token. */
    @PostMapping("/auth/me/verify-password")
    public Map<String, Boolean> verifyPassword(@RequestHeader(value = "Authorization", required = false) String auth,
                                               @RequestBody PasswordCheckRequest body) {
        Caller c = bearer.resolve(auth);
        boolean valid = body != null && body.password() != null && c.user().getPassword() != null
                && passwordEncoder.matches(body.password(), c.user().getPassword());
        return Map.of("valid", valid);
    }

    @PostMapping("/auth/users/lookup")
    public List<LookupEntry> lookup(@RequestHeader(value = "Authorization", required = false) String auth,
                                    @RequestBody LookupRequest body) {
        Caller c = bearer.resolve(auth);
        if (body == null || body.ids() == null || body.ids().isEmpty()) return List.of();
        if (body.ids().size() > MAX_LOOKUP) throw new BadRequestException("At most " + MAX_LOOKUP + " ids at a time");
        return tenants.db(c.customer()).find(Query.query(Criteria.where("id").in(body.ids())), User.class).stream()
                .map(u -> new LookupEntry(u.getId(), u.getUsername(), u.getFirstname(), u.getLastname()))
                .toList();
    }

    private static boolean tooLong(String s, int max) {
        return s != null && s.length() > max;
    }
}
