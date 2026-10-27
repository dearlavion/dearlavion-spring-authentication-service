package com.dearlavion.authservice.user.model;

/** Whether a privileged account has been approved by a superadmin. A missing value on an existing document counts as APPROVED. */
public enum ApprovalStatus {
    PENDING,
    APPROVED,
    REJECTED
}
