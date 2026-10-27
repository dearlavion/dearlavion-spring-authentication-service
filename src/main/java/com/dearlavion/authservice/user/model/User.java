package com.dearlavion.authservice.user.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * A user. Same `users` collection and field names as the Java v1 / NestJS v2 services so all
 * stacks read the same documents. Passwords are bcrypt hashes (interoperable across Spring's
 * BCryptPasswordEncoder and Node's bcryptjs). Lives in a per-customer `authentication-<customer>`
 * database, resolved dynamically at request time by {@link com.dearlavion.authservice.tenant.TenantService}
 * — never bound to one fixed database the way a plain MongoRepository would be.
 */
@Getter
@Setter
@Document(collection = "users")
public class User {

    @Id
    private String id;

    private String username;

    private String firstname;

    private String lastname;

    private String email;

    private String phone;

    private String password;

    private String image;
    /** Free-text profile blurb (set via PATCH /auth/me/profile); null for users who never set one. */
    private String bio;

    private Role activeProfile = Role.USER;

    private AuthType type = AuthType.SIMPLE;

    /** Soft-delete flag for admin user management — false blocks login without removing the
     * document, so orders/payments/kits elsewhere that reference this user by id aren't orphaned. */
    private boolean active = true;

    /** Approval state of a privileged account; null (every document written before this existed) means APPROVED. */
    private ApprovalStatus status;

    /** What an approved admin may do; null means BOTH, so admins that predate permissions keep full access. */
    private Permission permission;

    public ApprovalStatus effectiveStatus() {
        return status != null ? status : ApprovalStatus.APPROVED;
    }

    public Permission effectivePermission() {
        return permission != null ? permission : Permission.BOTH;
    }

    public boolean isApproved() {
        return effectiveStatus() == ApprovalStatus.APPROVED;
    }
}
