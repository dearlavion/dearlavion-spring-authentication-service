package com.dearlavion.authservice.user.model;

/** What an approved admin may do in their own project. A missing value on an existing document counts as BOTH. */
public enum Permission {
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
