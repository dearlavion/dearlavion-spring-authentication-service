package com.dearlavion.authservice.user.model;

/** Access role. ADMIN/STAFF are privileged (admin on consuming backends); USER is a normal user.
 * SUPERADMIN exists only in the security tenant and manages admins across every project. */
public enum Role {
    SUPERADMIN,
    ADMIN,
    STAFF,
    USER
}
