package com.dearlavion.authservice.auth.response;

import com.dearlavion.authservice.user.model.Permission;
import com.dearlavion.authservice.user.model.Role;

/** The shape core/notification/store-engine/booking-engine expect from POST /auth/verify. {@code permission} is
 * what a backend enforces for an admin (READ blocks writes); plain users carry BOTH and it only matters for ADMIN/STAFF. */
public record VerifyResult(boolean valid, String username, String email, String userId, Role activeProfile, String customer,
                           Permission permission) {
}
