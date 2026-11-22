package com.dearlavion.authservice.auth.response;

import com.dearlavion.authservice.user.model.Permission;
import com.dearlavion.authservice.user.model.Role;

import java.util.List;

/**
 * The shape core/notification/store-engine/booking-engine expect from POST /auth/verify. {@code permissions} are the permission
 * keys the user's role links, which is what a backend should check; {@code permission} is the older READ/MODIFY/BOTH/NONE view of
 * read and modify, kept for consumers that already read it. {@code roleId}/{@code roleName} are null for accounts without a role.
 */
public record VerifyResult(boolean valid, String username, String email, String userId, Role activeProfile, String customer,
                           Permission permission, String roleId, String roleName, List<String> permissions) {
}
