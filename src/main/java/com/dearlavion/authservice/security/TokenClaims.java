package com.dearlavion.authservice.security;

/** Verified token contents. {@code userId} (the {@code uid} claim) is null on tokens issued before it existed. */
public record TokenClaims(String username, String customer, String userId) {

    public TokenClaims(String username, String customer) {
        this(username, customer, null);
    }
}
