package com.dearlavion.authservice.user.response;

import com.dearlavion.authservice.user.model.ApprovalStatus;
import com.dearlavion.authservice.user.model.Permission;
import com.dearlavion.authservice.user.model.Role;

/** Public projection of a user (no password), returned by GET /auth/user/{username} and the
 * admin user-management endpoints. */
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
        Permission permission
) {
}
