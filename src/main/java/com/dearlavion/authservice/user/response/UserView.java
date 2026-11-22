package com.dearlavion.authservice.user.response;

import com.dearlavion.authservice.user.model.ApprovalStatus;
import com.dearlavion.authservice.user.model.Role;

import java.util.List;

/** Public projection of a user (no password), returned by GET /auth/user/{username} and the admin user-management
 * endpoints. {@code roleId}/{@code roleName} are the role they hold (null for accounts that predate roles) and
 * {@code permissions} what that gives them. */
public record UserView(
        String username,
        String email,
        String firstname,
        String lastname,
        String phone,
        String image,
        Role activeProfile,
        boolean active,
        ApprovalStatus status,
        String roleId,
        String roleName,
        List<String> permissions
) {
}
