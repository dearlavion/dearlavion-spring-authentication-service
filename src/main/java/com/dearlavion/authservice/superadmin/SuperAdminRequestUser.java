package com.dearlavion.authservice.superadmin;

/** The verified superadmin behind a /superadmin request, stored on the request by {@link SuperAdminAuthFilter}. */
public record SuperAdminRequestUser(String username) {
}
