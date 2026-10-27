package com.dearlavion.authservice.user.response;

import java.util.List;

/** One page of users plus the total that matched, for the superadmin lists. */
public record UserPage(List<UserView> items, long total, int page, int size) {
}
