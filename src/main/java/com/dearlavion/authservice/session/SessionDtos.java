package com.dearlavion.authservice.session;

import com.dearlavion.authservice.user.model.Role;

import java.util.List;

/** Request and response shapes for the cookie-session, profile and lookup endpoints. */
public final class SessionDtos {

    private SessionDtos() {}

    /** The caller's own account (no password hash). */
    public record ProfileView(String id, String username, String email, String firstname, String lastname,
                              String bio, String image, Role activeProfile, String customer) {}

    /** Access token for the Authorization header; the refresh token travels only in the cookie. */
    public record SessionResponse(String token, long expiresIn, ProfileView user) {}

    /** Null fields are left unchanged; send "" to clear the bio. */
    public record ProfileUpdateRequest(String firstname, String lastname, String bio) {}

    public record PasswordCheckRequest(String password) {}

    public record LookupRequest(List<String> ids) {}

    /** Just enough to show a name next to an id (e.g. a member list). */
    public record LookupEntry(String id, String username, String firstname, String lastname) {}
}
