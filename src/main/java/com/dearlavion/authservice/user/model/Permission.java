package com.dearlavion.authservice.user.model;

/** What an approved admin may do in their own project. A missing value on an existing document counts as BOTH.
 * NONE keeps the approved account but switches both access types off. */
public enum Permission {
    NONE,
    READ,
    MODIFY,
    BOTH;

    public boolean canRead() {
        return this == READ || this == BOTH;
    }

    public boolean canModify() {
        return this == MODIFY || this == BOTH;
    }
}
